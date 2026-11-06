//! Live check of tool calling on the local serving path, against a small
//! catalog model fetched through the node's own pinned downloader.
//!
//! Ignored by default: it downloads a few hundred megabytes and runs a model
//! on CPU. Run with `--ignored`; `TENZRO_LIVE_MODEL` picks the catalog id
//! (default `qwen3-0.6b`) and `TENZRO_MODELS_DIR` where it is stored.
//!
//! What it grades, for each prompt, in the manner of a tool-call conformance
//! suite: a reply to a prompt that needs the tool must call it
//! (`finish_reason` is then `tool_calls`), the call must name a declared
//! function, and its arguments must parse and satisfy the declared schema.
//! The tools are `strict`, so the serving path must refuse a call whose
//! arguments break the schema rather than return it. The test fails only if
//! a schema-invalid call gets through; how often the model calls a tool,
//! answers in prose, or is refused is a quality measurement, printed but not
//! asserted.
#![cfg(feature = "inference")]

// The model parser runs as this binary started again.
tenzro_node::enter_parse_jail_child_before_tests!();

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tenzro_model::hf_download::{DownloadProgress, DownloadState, HfDownloader, SourcePolicy};
use tenzro_model::{GenerationConfig, ModelRuntime};
use tenzro_node::openai_tools::{
    LocalChatError, OpenAIChatMessage, OpenAITool, ToolPlan, generate_local, validate_schema,
};

fn models_dir() -> PathBuf {
    std::env::var("TENZRO_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tenzro-live-models"))
}

#[tokio::test]
#[ignore]
async fn a_small_catalog_model_calls_declared_tools_with_valid_arguments() {
    tenzro_catalog::install_test_seed();
    let model_id = std::env::var("TENZRO_LIVE_MODEL").unwrap_or_else(|_| "qwen3-0.6b".into());
    let entry = tenzro_model::catalog::get_model_by_id(&model_id).expect("catalog entry");
    let dir = models_dir();
    std::fs::create_dir_all(&dir).unwrap();

    // Fetched at the pinned commit and hashed against the pinned SHA-256
    // before it is renamed into place.
    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: model_id.clone(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: 0,
    });
    let downloader = HfDownloader::new(dir.clone());
    let path = if downloader.is_downloaded(&model_id) {
        downloader.model_path(&model_id)
    } else {
        downloader
            .download_model(&entry, None, SourcePolicy::HuggingFace, tx)
            .await
            .expect("pinned download")
    };

    let runtime = Arc::new(ModelRuntime::new().expect("runtime"));
    runtime.load_model(&model_id, &path).await.expect("load");

    let tools: Vec<OpenAITool> = serde_json::from_value(json!([
        {"type": "function", "function": {
            "name": "get_weather",
            "description": "Current weather for a city",
            "strict": true,
            "parameters": {"type": "object",
                           "properties": {"city": {"type": "string"},
                                          "unit": {"type": "string", "enum": ["c", "f"]}},
                           "required": ["city"]}}},
        {"type": "function", "function": {
            "name": "convert_currency",
            "description": "Convert an amount between currencies",
            "strict": true,
            "parameters": {"type": "object",
                           "properties": {"amount": {"type": "number"},
                                          "from": {"type": "string"},
                                          "to": {"type": "string"}},
                           "required": ["amount", "from", "to"]}}}
    ]))
    .unwrap();
    let schema_of = |name: &str| {
        tools
            .iter()
            .find(|t| t.function.name == name)
            .and_then(|t| t.function.parameters.clone())
    };
    let plan = ToolPlan::from_request(Some(&tools), None).unwrap().unwrap();

    let prompts = [
        "What is the weather in Oslo right now?",
        "Is it raining in Lisbon? Use Fahrenheit.",
        "Convert 120 euros to US dollars.",
        "How many yen is 50 pounds?",
        "What's the temperature in Nairobi?",
        "Change 1000 Swiss francs into euros please.",
    ];
    let config = GenerationConfig {
        temperature: 0.0,
        max_tokens: 256,
        enable_thinking: Some(false),
        ..GenerationConfig::default()
    };

    let (mut called, mut prose, mut refused, mut invalid) = (0, 0, 0, Vec::new());
    for prompt in prompts {
        let messages = vec![OpenAIChatMessage::text("user".into(), prompt.into()).to_model()];
        match generate_local(&runtime, &model_id, &messages, &[], Some(&plan), &config).await {
            Ok(outcome) if outcome.tool_calls.is_empty() => {
                prose += 1;
                println!("PROSE  {prompt:?} -> {:?}", outcome.result.text);
            }
            Ok(outcome) => {
                assert_eq!(outcome.finish_reasons().0, "tool_calls");
                for call in &outcome.tool_calls {
                    let args: serde_json::Value =
                        serde_json::from_str(&call.function.arguments).expect("arguments are JSON");
                    let schema = schema_of(&call.function.name).expect("declared function");
                    if let Err(at) = validate_schema(&schema, &args, "$") {
                        invalid.push(format!("{prompt}: {} {args} at {at}", call.function.name));
                    }
                    println!("CALL   {prompt:?} -> {} {args}", call.function.name);
                }
                called += 1;
            }
            Err(LocalChatError::Tools(e)) => {
                refused += 1;
                println!("REFUSED {prompt:?} -> {}: {}", e.code, e.message);
            }
            Err(LocalChatError::Model(e)) => panic!("{prompt}: generation failed: {e}"),
        }
    }
    println!(
        "{model_id}: {called} tool calls, {prose} prose answers, {refused} refused by the contract, \
         {} schema-invalid calls passed through, of {}",
        invalid.len(),
        prompts.len()
    );
    assert!(invalid.is_empty(), "schema-invalid calls: {invalid:?}");
}
