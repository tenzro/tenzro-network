//! A model assigned to a hosted engine, served through the node's own model
//! runtime: the same claims, the same generation entry points and the same
//! token accounting as a llama.cpp model.
//!
//! The engine is a stand-in adapter (a short Python script speaking the
//! runtime host protocol) in a pinned environment. It runs in the real
//! confined runtime host, so this binary is also the confinement launcher and
//! has its own `main`. A kernel that refuses the confinement skips the run
//! with the reason.

#[cfg(unix)]
mod confined {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use praecise_host::Health;
    use tenzro_model::model_host::Engine;
    use tenzro_model::traffic::TrafficManager;
    use tenzro_model::{
        ChatMessage, EnginesConfig, EnvironmentPin, GenerationConfig, ModelError, ModelHost,
        ModelRuntime,
    };

    const MODEL: &str = "hosted-echo";

    const ADAPTER: &str = r#"import json, os, sys
for line in sys.stdin:
    req = json.loads(line)
    rid = req["id"]
    if req["op"] == "load":
        out = {"id": rid, "ok": True}
    else:
        prompt = req.get("prompt") or " ".join(m["content"] for m in req.get("messages", []))
        if "crash" in prompt:
            os._exit(3)
        text = "echo: " + prompt
        for piece in (text[:5], text[5:]):
            print(json.dumps({"id": rid, "event": {"text": piece}}), flush=True)
        out = {"id": rid, "ok": True, "text": text, "finish_reason": "stop",
               "usage": {"prompt_tokens": len(prompt.split()), "completion_tokens": 2}}
    print(json.dumps(out), flush=True)
"#;

    pub fn main() {
        praecise_host::sandbox::enter_if_requested();
        if !cfg!(target_os = "linux") || !Path::new("/usr/bin/python3").exists() {
            println!("hosted_engines: skipped (needs Linux and /usr/bin/python3)");
            return;
        }
        let dir =
            std::env::temp_dir().join(format!("tenzro-hosted-engines-{}", std::process::id()));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = rt.block_on(tenzro_model::access::as_node(run(&dir)));
        let _ = std::fs::remove_dir_all(&dir);
        match outcome {
            Ok(()) => println!("hosted_engines: ok"),
            Err(e) if e.contains("confinement refused") => {
                println!("hosted_engines: skipped, the kernel refuses the confinement: {e}")
            }
            Err(e) => panic!("{e}"),
        }
    }

    /// A pinned environment whose adapter is the stand-in above.
    fn environment(dir: &Path) -> EnvironmentPin {
        let root = dir.join("env");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/python3", root.join("bin/python3")).unwrap();
        std::fs::write(root.join(praecise_host::engine::ADAPTER_FILE), ADAPTER).unwrap();
        EnvironmentPin {
            backend: "transformers".into(),
            root: root.clone(),
            digest: praecise_host::engine::digest(&root).unwrap(),
        }
    }

    async fn run(dir: &Path) -> Result<(), String> {
        let model_dir = dir.join("checkpoint");
        std::fs::create_dir_all(&model_dir).unwrap();
        // A checkpoint carries the chat template its turns are rendered through;
        // this one renders each message's content alone, so the stand-in echoes
        // the user's words.
        std::fs::write(
            model_dir.join("chat_template.jinja"),
            "{% for m in messages %}{{ m['content'] }}{% endfor %}",
        )
        .unwrap();
        let config = EnginesConfig {
            scratch_dir: Some(dir.join("scratch")),
            environments: vec![environment(dir)],
            models: [(MODEL.to_string(), "transformers".to_string())].into(),
        };
        let host = Arc::new(ModelHost::with_engines(TrafficManager::default(), &config).unwrap());
        let runtime = ModelRuntime::with_host(Arc::clone(&host)).expect("runtime");
        assert_eq!(
            runtime.hosted_backend(MODEL).map(|b| b.as_str()),
            Some("transformers")
        );
        assert!(
            runtime.hosted_backend("some-gguf").is_none(),
            "unassigned models stay on llama.cpp"
        );

        runtime
            .load_hosted(MODEL, &model_dir, 1 << 20)
            .await
            .map_err(|e| e.to_string())?;
        assert!(runtime.is_loaded(MODEL));
        runtime
            .load_hosted(MODEL, &model_dir, 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            host.engine_status().len(),
            1,
            "a repeated load starts no second host"
        );

        one_engine_per_model(&host, &model_dir);
        served_through_the_runtime(&runtime).await;
        streamed_through_the_runtime(&runtime).await;
        a_crash_is_restarted(&runtime, &host).await;

        runtime.unload_model(MODEL).await.unwrap();
        assert!(host.engine_status().is_empty());
        host.claim(MODEL, Engine::Praecise).unwrap().commit();
        Ok(())
    }

    fn one_engine_per_model(host: &ModelHost, model_dir: &Path) {
        let refused = host.claim(MODEL, Engine::Praecise).err().unwrap();
        assert!(
            matches!(&refused, ModelError::EngineConflict { held_by, .. } if held_by == "transformers"),
            "{refused}"
        );
        let refused = host.serve_hosted(MODEL, model_dir, 1 << 20).unwrap_err();
        assert!(
            matches!(refused, ModelError::EngineConflict { .. }),
            "{refused}"
        );
        assert!(host.claim("onnx-model", Engine::Onnx("vision")).is_ok());
    }

    async fn served_through_the_runtime(runtime: &ModelRuntime) {
        let messages = [ChatMessage::new("user", "one two three")];
        let config = GenerationConfig {
            max_tokens: 16,
            ..Default::default()
        };
        let r = runtime
            .generate_chat(MODEL, &messages, &config)
            .await
            .unwrap();
        assert_eq!(r.text, "echo: one two three");
        assert_eq!((r.input_tokens, r.output_tokens), (3, 2));
        let r = runtime.generate(MODEL, "four five", &config).await.unwrap();
        assert_eq!((r.text.as_str(), r.input_tokens), ("echo: four five", 2));
    }

    async fn streamed_through_the_runtime(runtime: &ModelRuntime) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let messages = [ChatMessage::new("user", "stream me")];
        let config = GenerationConfig {
            max_tokens: 16,
            ..Default::default()
        };
        let r = runtime
            .generate_chat_stream(MODEL, &messages, &config, tx, None)
            .await
            .unwrap();
        let mut streamed = String::new();
        while let Some(piece) = rx.recv().await {
            streamed.push_str(&piece);
        }
        assert_eq!(streamed, r.text);
    }

    async fn a_crash_is_restarted(runtime: &ModelRuntime, host: &ModelHost) {
        let config = GenerationConfig {
            max_tokens: 16,
            ..Default::default()
        };
        let crashed = runtime.generate(MODEL, "crash", &config).await.unwrap_err();
        assert!(crashed.to_string().contains("exited"), "{crashed}");
        let deadline = Instant::now() + Duration::from_secs(30);
        while host.engine_status()[0].health != (Health::Running { restarts: 1 }) {
            assert!(Instant::now() < deadline, "{:?}", host.engine_status());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(runtime.generate(MODEL, "after", &config).await.is_ok());
    }
}

#[cfg(unix)]
fn main() {
    confined::main();
}

/// The runtime-host confinement is Linux namespaces and Landlock; nothing here
/// runs on another platform, and this line says so rather than passing.
#[cfg(not(unix))]
fn main() {
    println!("hosted_engines: NOT RUN, the runtime-host confinement needs Linux");
}
