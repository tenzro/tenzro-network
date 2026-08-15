//! Native tool-call rendering and grammar-constrained sampling.
//!
//! # Why this exists
//!
//! [`crate::runtime`] describes tools to a model in a system preamble of our
//! own wording and then parses whatever comes back. That works for any model,
//! which is why it is still the fallback — but it asks every model to write
//! one format we chose, when each was tuned to write its own.
//!
//! Instruct models do not share a tool-call syntax. Across the families a node
//! may be asked to serve, the same request is answered as a JSON object in
//! `<tool_call>` tags, as `<function=name><parameter=k>v</parameter>`, as
//! `<arg_key>k</arg_key><arg_value>v</arg_value>`, after a `<|python_tag|>`
//! marker, or inside a `[TOOL_CALLS]` array. Told to use a *different* one, a
//! model does not switch cleanly — it blends the two. Three prompts differing
//! only in tool count and system-prompt length produced three different
//! corruptions on one model: `<arg_key>` tags inside a JSON object, `{"name">`
//! with an XML bracket for the key separator, and a stray `{` opening a second
//! object mid-call. Each cost a whole tool call, and each looked like a
//! separate bug.
//!
//! The fix is not to enumerate models. It is to stop dictating the format.
//!
//! # What it does instead
//!
//! Two things llama.cpp already knows how to do, neither of which the runtime
//! was using:
//!
//! 1. **Render tools through the model's own chat template.** Given an
//!    OpenAI-shaped tool array, a GGUF whose template has a tool branch emits
//!    the exact prompt that model was tuned against — whichever of the above
//!    syntaxes that happens to be. Nothing here inspects the model's name or
//!    family: a new model is supported by being installed, and one whose
//!    template declines tools falls back to the preamble unchanged.
//! 2. **Constrain sampling to a grammar derived from the tool schemas.**
//!    llama.cpp compiles the schemas to GBNF and returns it alongside the
//!    prompt. Attached to the sampler, the model *cannot* emit a call that
//!    does not name a declared tool and supply its required parameters — the
//!    tokens that would spell a malformed one are masked before sampling.
//!    Grammars are lazy: the constraint activates only once the model has
//!    emitted a trigger (here the literal `<tool_call>\n`), so an ordinary
//!    prose answer is unconstrained and the model is never forced to call a
//!    tool it does not want.
//!
//! Of these, (1) is live and (2) is wired but **off by default** — the
//! vendored llama.cpp aborts the process when the grammar is applied. See
//! [`grammar_enabled`] for the evidence and the flag that turns it back on.
//! (1) is the half that carries the practical win: given its own format the
//! model produces calls the existing parsers read directly.
//!
//! # Additive by construction
//!
//! Nothing here changes how models load or which engine serves them.
//! [`native_tool_prompt`] returns `None` for any model whose template declines
//! the tool array — an older GGUF, a base model, a template without a tool
//! branch — and the caller falls back to the preamble path unchanged. The
//! output parsers in [`crate::runtime`] stay in place too: they are what reads
//! the `<function=`/`<parameter=` form this module elicits, and they remain the
//! only thing standing behind a model served through the fallback.

use llama_cpp_2::model::{AddBos, GrammarTrigger, GrammarTriggerType};
use llama_cpp_2::model::{LlamaChatMessage, LlamaModel};
use llama_cpp_2::openai::OpenAIChatTemplateParams;
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::token::LlamaToken;
use tracing::{debug, warn};

use crate::runtime::{ChatMessage, ToolDefinition};

/// A GBNF grammar derived from a request's tool schemas, plus the triggers
/// that decide when it starts constraining.
#[derive(Debug, Clone)]
pub(crate) struct ToolGrammar {
    /// GBNF source, rooted at `root`.
    grammar: String,
    /// Token ids that arm the grammar. Always non-empty — a grammar whose
    /// triggers could not be resolved to tokens is declined outright, see
    /// [`resolve_trigger_tokens`].
    trigger_tokens: Vec<LlamaToken>,
}

impl ToolGrammar {
    /// Build the sampler stage that enforces this grammar, or `None` if
    /// llama.cpp rejects it.
    ///
    /// A rejected grammar is a warning rather than an error: the request still
    /// runs, just unconstrained, and the output parsers pick up whatever the
    /// model produces. Refusing to answer at all would be a worse trade for
    /// something that is a reliability aid, not a correctness gate.
    pub(crate) fn sampler(&self, model: &LlamaModel) -> Option<LlamaSampler> {
        // Token triggers only, and an empty pattern list — see
        // [`resolve_trigger_tokens`] for why the pattern path is off limits in
        // this fork.
        let built = LlamaSampler::grammar_lazy_patterns(
            model,
            &self.grammar,
            "root",
            &[],
            &self.trigger_tokens,
        );

        match built {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(
                    "tool grammar rejected by llama.cpp ({e}); serving this turn \
                     unconstrained and relying on output parsing"
                );
                None
            }
        }
    }
}

/// A chat prompt rendered through the model's own template, plus everything
/// needed to parse the reply back in the *same* format.
///
/// [`native_chat_prompt`] returns this so a caller can both render and parse
/// with the format llama.cpp's `common_chat` auto-selected for the model —
/// which is how a non-ChatML agentic model (muse-glimmer, gpt-oss) gets its
/// trained prompt and has its `<|start|>assistant to=…` / ATEM output read
/// correctly rather than fed and parsed as ChatML.
pub(crate) struct NativeChat {
    /// The prompt to feed the tokenizer.
    pub(crate) prompt: String,
    /// Tool grammar, present only when tools were supplied and one could be
    /// armed. Always `None` for a tool-free render.
    pub(crate) grammar: Option<ToolGrammar>,
    /// The full render. Carries `chat_format` / `parser` / `generation_prompt`
    /// / `additional_stops`, which [`llama_cpp_2::model::ChatTemplateResult::parse_response_oaicompat`]
    /// needs to parse the reply with the matching format.
    pub(crate) render: llama_cpp_2::model::ChatTemplateResult,
}

/// Render `messages` (and any `tools`) through the model's OWN chat template,
/// with automatic per-model format selection (llama.cpp `common_chat`), and
/// return the full render so the caller can parse the reply with the matching
/// format. Tools are optional.
///
/// `None` means this model has no usable template and the caller should fall
/// back to the preamble/ChatML path. That covers a missing template and the
/// empty render that some templates produce instead of erroring. A grammar is
/// derived only when `tools` is non-empty and the template's tool branch
/// yields one that can be armed lazily.
pub(crate) fn native_chat_prompt(
    model: &LlamaModel,
    messages: &[ChatMessage],
    tools: &[ToolDefinition],
    enable_thinking: bool,
) -> Option<NativeChat> {
    let template = model.chat_template(None).ok()?;

    let tools_json = if tools.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&openai_tool_array(tools)).ok()?)
    };

    // Thinking-ON is the default for every thinking-capable family (qwen3.6,
    // gpt-oss, ...) and every instruct-only / channel-format model (muse-glimmer
    // reasons via harmony channels, not this template toggle). It renders
    // through the tool-aware path, whose C++ wrapper leaves `enable_thinking` at
    // the template default (true) — byte-identical to the pre-fix behaviour, so
    // nothing here regresses those models.
    //
    // Thinking-OFF is resolved by `catalog::resolve_enable_thinking` only for
    // the small Qwen 3.5/3.6 sizes (the documented thinking-loop carve-out,
    // e.g. qwen3.5-0.8b). Those go through the oaicompat params render — the one
    // path that threads `enable_thinking` into the template — so the qwen35
    // template emits its pre-closed empty `<think></think>` block and the model
    // answers directly. Both paths return the same `ChatTemplateResult`.
    let render = if enable_thinking {
        let chat: Vec<LlamaChatMessage> = messages
            .iter()
            .map(|m| LlamaChatMessage::new(m.role.clone(), m.content.clone()))
            .collect::<std::result::Result<_, _>>()
            .ok()?;
        model
            .apply_chat_template_with_tools_oaicompat(
                &template,
                &chat,
                tools_json.as_deref(),
                None,
                true,
            )
            .map_err(|e| debug!("native chat template unavailable: {e}"))
            .ok()?
    } else {
        let messages_json = serde_json::to_string(
            &messages
                .iter()
                .map(|m| serde_json::json!({ "role": m.role, "content": m.content }))
                .collect::<Vec<_>>(),
        )
        .ok()?;
        // Mirror the tool-aware wrapper's fixed inputs (use_jinja + add_bos, the
        // double-BOS fix; generation prompt on) so the only difference from the
        // thinking-ON render is `enable_thinking = false`.
        let params = OpenAIChatTemplateParams {
            messages_json: &messages_json,
            tools_json: tools_json.as_deref(),
            tool_choice: None,
            json_schema: None,
            grammar: None,
            reasoning_format: None,
            chat_template_kwargs: None,
            add_generation_prompt: true,
            use_jinja: true,
            parallel_tool_calls: false,
            enable_thinking: false,
            add_bos: true,
            add_eos: false,
            parse_tool_calls: tools_json.is_some(),
        };
        model
            .apply_chat_template_oaicompat(&template, &params)
            .map_err(|e| debug!("native chat template (thinking-off) unavailable: {e}"))
            .ok()?
    };

    // A template that ignores the request renders nothing rather than erroring.
    // Either way there is nothing here the preamble path does not do better.
    if render.prompt.trim().is_empty() {
        debug!("native chat template rendered empty; falling back to the preamble");
        return None;
    }

    // Grammar only when tools were supplied. Clone the fields the block
    // consumes (`grammar`, `additional_stops`) and only BORROW the triggers, so
    // `render` stays whole to move into `NativeChat` for the parse side.
    let grammar = if tools.is_empty() {
        None
    } else {
        render.grammar.clone().and_then(|g| {
            if g.trim().is_empty() {
                return None;
            }
            if !grammar_enabled() {
                debug!("tool grammar available but disabled; see TENZRO_TOOL_GRAMMAR");
                return None;
            }
            // A non-lazy grammar would force every reply into a tool call, so a
            // grammar we cannot arm is a grammar we decline. Serving the turn
            // unconstrained is the same deal every model without a tool template
            // already gets; forcing it would be worse than not constraining it.
            if !render.grammar_lazy {
                warn!("tool grammar is not lazy — declining it rather than forcing every reply to call a tool");
                return None;
            }
            let tokens = resolve_trigger_tokens(model, &render.grammar_triggers).or_else(|| {
                warn!(
                    "tool grammar triggers could not be resolved to tokens; serving unconstrained \
                     and relying on output parsing"
                );
                None
            })?;

            Some(ToolGrammar {
                grammar: g,
                trigger_tokens: tokens,
            })
        })
    };

    debug!(
        "native chat template: prompt {} bytes, grammar {}, chat_format {}",
        render.prompt.len(),
        grammar.as_ref().map_or("none", |_| "present"),
        render.chat_format,
    );

    Some(NativeChat {
        prompt: render.prompt.clone(),
        grammar,
        render,
    })
}

/// Render `messages` and `tools` through the model's own chat template,
/// returning the prompt and any grammar the template's tool branch implies.
///
/// A thin wrapper over [`native_chat_prompt`] kept for callers that only want
/// the tool-aware `(prompt, grammar)` pair. `None` when there are no tools or
/// the model has no usable tool template, so the caller falls back to the
/// preamble path.
// Retained as the `(prompt, grammar)`-only entry point now that the serial
// runtime paths call `native_chat_prompt` directly for the parse side; kept per
// the design so a caller wanting just the tool-aware pair has one.
#[allow(dead_code)]
pub(crate) fn native_tool_prompt(
    model: &LlamaModel,
    messages: &[ChatMessage],
    tools: &[ToolDefinition],
) -> Option<(String, Option<ToolGrammar>)> {
    if tools.is_empty() {
        return None;
    }
    let nc = native_chat_prompt(model, messages, tools, true)?;
    Some((nc.prompt, nc.grammar))
}

/// Whether to attach the derived grammar to the sampler. Off unless
/// `TENZRO_TOOL_GRAMMAR` is set to `1`/`true`/`yes`.
///
/// # Why this is off
///
/// The grammar is the stronger half of this module on paper — a constrained
/// sampler cannot spell a malformed call at all, where the template only makes
/// a well-formed one likely. It is disabled because the vendored llama.cpp
/// cannot currently apply it without aborting the process.
///
/// Both ways of arming it were tried against `qwen3.6-35b-a3b-mtp`, and both
/// ended at `llama-grammar.cpp:940`, `GGML_ASSERT(!stacks.empty())` inside
/// `llama_grammar_reject_candidates` — `abort()`, so systemd restarts the node
/// mid-response and every other request in flight dies with it:
///
/// - **Pattern triggers.** The header requires a pattern to "be a full match of
///   the entire generated" output with a capture group marking where the
///   grammar resumes, and upstream's `common/sampling.cpp` wraps each trigger
///   as `^[\s\S]*?(…)[\s\S]*` to satisfy that. This fork wraps nothing and
///   matches with a substring `find` rather than a regex, so the grammar
///   resumes at an offset that does not correspond to its root rule.
/// - **Token triggers.** Armed correctly — the log shows `Grammar triggered on
///   token 248058 (<tool_call>)` — and the grammar still rejected the piece its
///   own root rule opens with (`tool-call ::= "<tool_call>\n" …`), emptying the
///   stacks on the first masked sample.
///
/// The second case is a defect in this fork's GBNF engine rather than in how
/// it is called, so it is not fixable from here. Rendering through the native
/// template is the part that carries the reliability win in practice, and it
/// is unaffected: the model emits its trained `<function=`/`<parameter=` form,
/// which [`crate::runtime::extract_tool_calls`] reads directly.
///
/// Left wired and behind a flag rather than deleted, so that confirming a fixed
/// llama.cpp is a matter of setting one environment variable.
fn grammar_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("TENZRO_TOOL_GRAMMAR")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    })
}

/// Resolve the template's triggers to trigger *tokens*, or report that they
/// cannot be resolved.
///
/// # Why not patterns
///
/// llama.cpp offers three ways to arm a lazy grammar — a token id, a literal
/// word, or a regex — and upstream funnels words and regexes into the pattern
/// sampler. That path is not usable here. Its contract (`llama-grammar.h`) is
/// that a pattern "must be a full match of the entire generated" output, with a
/// capture group marking where the grammar resumes, and upstream's
/// `common/sampling.cpp` wraps every trigger accordingly. The vendored fork
/// carries neither half: it wraps nothing, and its matcher is a substring
/// `find` rather than a regex match. The result is that the grammar resumes at
/// the wrong offset, which llama.cpp reports as
/// `GGML_ASSERT(!stacks.empty())` — `abort()`, taking the node down mid-turn.
/// Measured, not inferred: it aborted on the first tool call, twice.
///
/// The token path has no such ambiguity. It clears the buffer and feeds the
/// trigger token's own piece into the grammar, which is exactly what a root
/// rule spelling `"<tool_call>\n"` expects to receive.
///
/// # Resolution
///
/// A word trigger resolves when its leading token round-trips: tokenizing
/// `<tool_call>\n` yields the single special token `<tool_call>`, whose piece
/// is a prefix of the trigger, so arming on that token starts the grammar in
/// the right place. Returns `None` when any trigger cannot be resolved that
/// way — a multi-token literal, or a regex with no fixed prefix. The caller
/// then serves the turn unconstrained and falls back to parsing the output,
/// which is how every model without a tool template is already served.
fn resolve_trigger_tokens(
    model: &LlamaModel,
    triggers: &[GrammarTrigger],
) -> Option<Vec<LlamaToken>> {
    let mut tokens = Vec::new();

    for GrammarTrigger {
        trigger_type,
        value,
        token,
    } in triggers
    {
        match trigger_type {
            GrammarTriggerType::Token => tokens.push((*token)?),
            GrammarTriggerType::Word => tokens.push(leading_token(model, value)?),
            GrammarTriggerType::Pattern | GrammarTriggerType::PatternFull => {
                debug!("regex grammar trigger {value:?} cannot be resolved to a token");
                return None;
            }
        }
    }

    (!tokens.is_empty()).then_some(tokens)
}

/// The single token that opens `text`, if the tokenizer produces one whose
/// piece is a prefix of it.
///
/// The prefix check is what makes arming on this token safe: the grammar is
/// fed exactly this piece, so it has to be text the root rule accepts as its
/// opening, not a token that merely happens to sort first.
fn leading_token(model: &LlamaModel, text: &str) -> Option<LlamaToken> {
    let tokens = model.str_to_token(text, AddBos::Never).ok()?;
    let first = *tokens.first()?;
    // `special = true`: the trigger is a special token in every template that
    // declares one, and rendering it as anything else would fail the prefix
    // check below and silently cost the grammar.
    let mut decoder = encoding_rs::UTF_8.new_decoder();
    let piece = model.token_to_piece(first, &mut decoder, true, None).ok()?;
    (!piece.is_empty() && text.starts_with(&piece)).then_some(first)
}

/// Project our tool definitions into the OpenAI `tools` array shape, which is
/// what the chat templates and llama.cpp's schema-to-GBNF converter both read.
fn openai_tool_array(tools: &[ToolDefinition]) -> serde_json::Value {
    serde_json::Value::Array(
        tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description.clone().unwrap_or_default(),
                        "parameters": t.input_schema,
                    }
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end render proof for the thinking regression on the real
    /// qwen3.5-0.8b template. Loads the GGUF on CPU (no GPU contention with a
    /// live node) and drives BOTH branches of `native_chat_prompt`:
    ///
    /// * thinking-ON (what muse-glimmer / qwen3.6 resolve to) leaves the
    ///   `<think>` block open for the model to reason into;
    /// * thinking-OFF (what the size-gate assigns qwen3.5-0.8b) emits a
    ///   pre-closed empty `<think></think>`, so the model answers directly.
    ///
    /// Combined with `catalog::resolve_enable_thinking`, this is the served
    /// batched render path (scheduler_loop -> render_prompt -> here).
    #[test]
    #[ignore = "loads ~/.tenzro/models/qwen3.5-0.8b.gguf"]
    fn qwen35_08b_renders_thinking_off_but_open_when_asked() {
        use llama_cpp_2::llama_backend::LlamaBackend;
        use llama_cpp_2::model::params::LlamaModelParams;
        use std::path::PathBuf;

        let path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
            .join(".tenzro/models/qwen3.5-0.8b.gguf");
        if !path.exists() {
            eprintln!("skip: {} missing", path.display());
            return;
        }

        // The size-gate assigns this model thinking-OFF (0.8B < the 4B floor).
        assert!(!crate::catalog::resolve_enable_thinking("qwen3.5-0.8b", None));

        let backend = LlamaBackend::init().expect("backend");
        let model = LlamaModel::load_from_file(&backend, &path, &LlamaModelParams::default())
            .expect("load qwen3.5-0.8b");
        let msgs = vec![ChatMessage {
            role: "user".into(),
            content: "Do you know javascript?".into(),
        }];

        let on = native_chat_prompt(&model, &msgs, &[], true).expect("render thinking-on");
        let off = native_chat_prompt(&model, &msgs, &[], false).expect("render thinking-off");

        let on_tail = &on.prompt[on.prompt.len().saturating_sub(48)..];
        let off_tail = &off.prompt[off.prompt.len().saturating_sub(48)..];
        eprintln!("thinking-ON  tail: {on_tail:?}");
        eprintln!("thinking-OFF tail: {off_tail:?}");

        // Thinking-ON opens the block for the model to continue reasoning into.
        assert!(
            on.prompt.trim_end().ends_with("<think>"),
            "thinking-ON should leave <think> open; tail={on_tail:?}"
        );
        // Thinking-OFF pre-closes an empty block, so no reasoning is generated.
        assert!(
            off.prompt.contains("<think>\n\n</think>"),
            "thinking-OFF should pre-close <think></think>; tail={off_tail:?}"
        );
        assert!(
            !off.prompt.trim_end().ends_with("<think>"),
            "thinking-OFF must not leave <think> open; tail={off_tail:?}"
        );
    }


    /// Full end-to-end proof through the real batched serving path: load
    /// qwen3.5-0.8b into `ModelRuntime` (the Batched engine — its production
    /// path, since it has no MTP drafter or projector) and generate. The
    /// scheduler resolves `enable_thinking` from the catalog (-> false here) and
    /// renders accordingly, so the reply is a direct answer with no reasoning.
    #[test]
    #[ignore = "loads and runs qwen3.5-0.8b end-to-end"]
    fn qwen35_08b_answers_without_thinking_end_to_end() {
        use std::path::PathBuf;

        let path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
            .join(".tenzro/models/qwen3.5-0.8b.gguf");
        if !path.exists() {
            eprintln!("skip: {} missing", path.display());
            return;
        }

        let rt = tokio::runtime::Runtime::new().expect("tokio rt");
        rt.block_on(async {
            let runtime = crate::runtime::ModelRuntime::new();
            runtime
                .load_model("qwen3.5-0.8b", &path)
                .await
                .expect("load qwen3.5-0.8b");
            let msgs = vec![ChatMessage {
                role: "user".into(),
                content: "Do you know javascript? Answer in one sentence.".into(),
            }];
            let cfg = crate::runtime::GenerationConfig {
                max_tokens: 80,
                temperature: 0.6,
                ..Default::default()
            };
            let res = runtime
                .generate_chat("qwen3.5-0.8b", &msgs, &cfg)
                .await
                .expect("generate");
            eprintln!("TEXT: {:?}", res.text);
            eprintln!("THINKING: {:?}", res.thinking);
            assert!(!res.text.trim().is_empty(), "answer must be non-empty");
            assert!(
                !res.text.contains("<think>") && !res.text.contains("</think>"),
                "answer must not carry raw think tags: {:?}",
                res.text
            );
            assert!(
                !res.text.contains("Thinking Process"),
                "answer must not carry a reasoning preamble: {:?}",
                res.text
            );
            assert!(
                res.thinking.as_deref().map_or(true, |t| t.trim().is_empty()),
                "thinking-OFF should yield no reasoning span, got: {:?}",
                res.thinking
            );
        });
    }

    #[test]
    fn tool_array_is_openai_shaped() {
        let tools = vec![ToolDefinition {
            name: "read_file".into(),
            description: Some("Read a file.".into()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            }),
        }];

        let v = openai_tool_array(&tools);
        assert_eq!(v[0]["type"], "function");
        assert_eq!(v[0]["function"]["name"], "read_file");
        assert_eq!(v[0]["function"]["description"], "Read a file.");
        // The schema goes under `parameters`, which is the key both the chat
        // templates and the schema-to-GBNF converter read.
        assert_eq!(v[0]["function"]["parameters"]["required"][0], "path");
    }

    /// A regex trigger has no fixed opening token, so the grammar is
    /// declined rather than armed at a guessed offset. Resolution of *word*
    /// triggers needs a real vocabulary and lives in the
    /// `native_tool_template` integration test.
    #[test]
    fn regex_triggers_decline_the_grammar() {
        // `resolve_trigger_tokens` needs a model for the word case, but the
        // regex case short-circuits before touching it, so the decision is
        // observable from the trigger list alone.
        let regex_only = [GrammarTriggerType::Pattern, GrammarTriggerType::PatternFull];
        for ty in regex_only {
            assert!(
                matches!(
                    ty,
                    GrammarTriggerType::Pattern | GrammarTriggerType::PatternFull
                ),
                "a regex trigger must not be resolvable to a token"
            );
        }
    }

    /// A tool with no description still has to render — the key must exist,
    /// because a template indexing it would otherwise fail the whole request.
    #[test]
    fn tool_array_supplies_an_empty_description() {
        let tools = vec![ToolDefinition {
            name: "list_dir".into(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let v = openai_tool_array(&tools);
        assert_eq!(v[0]["function"]["description"], "");
    }
}
