//! Decisions through the answer cache: a recorded campaign replays bit for
//! bit, on any thread count, and a replay without its answers fails.

use std::sync::{Arc, Mutex};

use tenzro_econsim::campaign::{Spec, run};
use tenzro_econsim::decision::{
    Cache, Decode, Mode, ModelPolicy, ModelRef, Policy, Reply, Request, Template, Transport,
};
use tenzro_econsim::economy::{Economy, Market, RunConfig, RunOutcome};
use tenzro_econsim::gsa;

/// Answers with a menu word picked by the seed, and counts its calls.
struct Stub(Mutex<u64>);

impl Transport for Stub {
    fn complete(&self, req: &Request<'_>) -> Result<Reply, String> {
        *self.0.lock().unwrap() += 1;
        let tail = req
            .prompt
            .split("one word from: ")
            .nth(1)
            .ok_or("no menu in the request")?;
        let menu: Vec<&str> = tail
            .split(['.', '"'])
            .next()
            .unwrap_or("")
            .split(", ")
            .collect();
        let word = menu[(req.seed % menu.len() as u64) as usize];
        Ok(Reply {
            text: format!("{word}\n"),
            receipt: Some(serde_json::json!({ "seed": req.seed })),
            cost_wei: Some("1000".into()),
            settlement: Some(serde_json::json!({ "channel": true })),
            input_tokens: Some(100),
            output_tokens: Some(1),
        })
    }
}

fn model(id: &str, b: &str) -> ModelRef {
    ModelRef {
        id: id.into(),
        hash: b.repeat(32),
    }
}

fn cfg(policy: Policy) -> RunConfig {
    let mut c = RunConfig::scenario(Market::Flat, 4, 15);
    c.decision_agents = 2;
    c.policy = policy;
    c
}

fn bytes(mut o: RunOutcome) -> String {
    o.wall_s = 0.0;
    serde_json::to_string(&o).unwrap()
}

#[test]
fn a_recorded_cache_replays_identically_on_any_thread_count() {
    let stub = Arc::new(Stub(Mutex::new(0)));
    let m = model("test-model", "ab");
    let rec = Arc::new(
        ModelPolicy::new(
            m.clone(),
            Template::Lines1,
            Decode::default(),
            Mode::Record,
            Cache::default(),
            Some(stub.clone()),
        )
        .unwrap(),
    );
    let recorded = Economy::new(cfg(Policy(rec.clone()))).run();
    assert!(
        recorded.decision_error.is_none(),
        "{:?}",
        recorded.decision_error
    );
    let calls = *stub.0.lock().unwrap();
    assert!(calls >= 24, "calls {calls}");
    let cache = rec.cache();
    assert_eq!(cache.entries.len() as u64, calls);
    let st = rec.stats();
    assert_eq!((st.calls, st.receipts, st.settled), (calls, calls, calls));
    assert_eq!(st.invalid, 0);
    let hash = cache.manifest_hash();

    let replay = || {
        Policy(Arc::new(
            ModelPolicy::new(
                m.clone(),
                Template::Lines1,
                Decode::default(),
                Mode::Replay,
                cache.clone(),
                None,
            )
            .unwrap(),
        ))
    };
    let one = gsa::run_all(vec![cfg(replay()), cfg(replay())], 1);
    let two = gsa::run_all(vec![cfg(replay()), cfg(replay())], 2);
    let want = bytes(recorded);
    for o in one.into_iter().chain(two) {
        assert!(o.decision_error.is_none());
        assert_eq!(bytes(o), want);
    }
    assert_eq!(cache.manifest_hash(), hash);
    // The policy changed the run: the rule run differs.
    let rules = Economy::new(cfg(Policy::default())).run();
    assert_ne!(bytes(rules), want);
}

#[test]
fn a_replay_without_its_answers_fails_the_run() {
    let p = ModelPolicy::new(
        model("test-model", "ab"),
        Template::Json1,
        Decode::default(),
        Mode::Replay,
        Cache::default(),
        None,
    )
    .unwrap();
    let o = Economy::new(cfg(Policy(Arc::new(p)))).run();
    let e = o.decision_error.expect("a miss fails the run");
    assert!(e.starts_with("replay: no cached answer"), "{e}");
    assert!(o.days.is_empty());
}

#[test]
fn the_rule_policy_is_the_simulation_itself() {
    let a = Economy::new(cfg(Policy::default())).run();
    let mut c = cfg(Policy::default());
    c.decision_agents = 5;
    let b = Economy::new(c).run();
    assert_eq!(bytes(a), bytes(b));
}

#[test]
fn a_campaign_reports_robustness_only_across_models_and_templates() {
    let stub: Arc<dyn Transport> = Arc::new(Stub(Mutex::new(0)));
    let spec = Spec {
        market: Market::Flat,
        days: 8,
        seed: 3,
        agents: 1,
        models: vec![model("a", "ab"), model("b", "cd")],
        templates: vec![Template::Lines1, Template::Prose1],
        decode: Decode::default(),
        mode: Mode::Record,
    };
    let (m, cache) = run(&spec, Cache::default(), Some(stub)).unwrap();
    assert_eq!(m.pairs.len(), 4);
    assert!(m.accounting.agree);
    assert_eq!(m.cache_entries, cache.entries.len());
    assert_ne!(m.cache_hash_in, m.cache_hash_out);
    assert!(m.robustness.iter().all(|r| r.deltas.len() == 4));
    let replay = Spec {
        mode: Mode::Replay,
        ..spec.clone()
    };
    let (r, after) = run(&replay, cache.clone(), None).unwrap();
    assert_eq!(after, cache);
    assert_eq!(r.cache_hash_in, r.cache_hash_out);
    assert_eq!(r.accounting.calls, 0);
    for (a, b) in m.pairs.iter().zip(&r.pairs) {
        assert_eq!(a.measures, b.measures);
    }
    let one_model = Spec {
        models: vec![model("a", "ab")],
        ..replay
    };
    let (e, _) = run(&one_model, cache, None).unwrap();
    assert!(e.robustness.iter().all(|r| r.verdict != "holds"));
}
