//! Setup as data.
//!
//! The plan is the one the terminal draws ([`journey::plan`]) turned into
//! JSON, and a step is run by the code the terminal runs ([`runner`]). What
//! is added here is what a shell without a terminal needs: the one question
//! as the plan's first step, and where each step stands, kept in a file so
//! setup picks up where it stopped.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{INVALID_PARAMS, REFUSED, error};
use crate::onboarding::role::JoinRole;
use crate::tui::detect::{self, Finding, Machine, Net};
use crate::tui::journey::{self, Action, Blocked, Gate, Offer, Opts, Path, Step};
use crate::tui::runner::{self, Begun, Msg, Running};
use crate::tui::theme::Word;

/// The id of the plan's first step: the one question.
const ROLE: &str = "role";

/// What a step that has to be done says when asked to be skipped.
const NOT_SKIPPABLE: &str = "This step cannot be skipped";

/// Why a step that carries a caution was not started.
const NOT_CONFIRMED: &str = "This step carries a caution: run it again with confirm set to the step's id once the caution is read";

/// The file setup's progress is kept in, beside the settings.
const PROGRESS_FILE: &str = "setup-progress.json";

/// How long what was found on this machine is believed.
const FOUND_KEPT: Duration = Duration::from_secs(30);

/// The answers setup offers to the one question, each with the name a shell
/// gives it and the role whose stake it needs.
const PATHS: [(&str, Path, JoinRole); 2] = [
    ("validate", Path::Validate, JoinRole::Validator),
    ("operate", Path::Provide, JoinRole::ModelProvider),
];

fn path_named(name: &str) -> Option<(&'static str, Path)> {
    PATHS
        .iter()
        .find(|(id, ..)| *id == name)
        .map(|(id, path, _)| (*id, *path))
}

/// What was found on this machine and on the network, and the settings the
/// plan is drawn with.
#[derive(Clone)]
pub(crate) struct Found {
    pub(crate) machine: Machine,
    pub(crate) net: Net,
    pub(crate) opts: Opts,
}

/// Something that looks at this machine.
pub(crate) type Look = Box<dyn Fn() -> Pin<Box<dyn Future<Output = Found> + Send>> + Send + Sync>;

/// Look at this machine and ask the network, as the terminal does when it
/// opens.
fn look() -> Pin<Box<dyn Future<Output = Found> + Send>> {
    Box::pin(async {
        let rpc = crate::tui::first_run_rpc();
        let (machine, net) = tokio::join!(detect::probe(), detect::check_network(&rpc));
        let opts = Opts::defaults(&machine, &rpc);
        Found { machine, net, opts }
    })
}

/// How a step ended.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum End {
    Done,
    Skipped,
    Failed,
}

/// A step that ended, as it is kept.
#[derive(Clone, Serialize, Deserialize)]
struct Ended {
    state: End,
    /// Why it failed.
    result: Option<String>,
    /// The last thing it said.
    progress: Option<String>,
}

/// Setup's progress as the file holds it: the answer to the one question,
/// and the steps that ended, under the answer they belong to.
#[derive(Default, Serialize, Deserialize)]
struct Kept {
    path: Option<String>,
    steps: BTreeMap<String, BTreeMap<String, Ended>>,
}

/// A step under way.
#[derive(Default)]
struct Live {
    /// It waits for the node rather than running a command.
    waiting: bool,
    /// The last thing it said.
    progress: Option<String>,
}

#[derive(Default)]
struct Inner {
    kept: Kept,
    /// Steps under way, by answer and step id.
    live: HashMap<(&'static str, &'static str), Live>,
    found: Option<(Instant, Arc<Found>)>,
}

impl Inner {
    fn chosen(&self) -> Option<(&'static str, Path)> {
        self.kept.path.as_deref().and_then(path_named)
    }

    fn ended(&self, path: &str, step: &str) -> Option<&Ended> {
        self.kept.steps.get(path)?.get(step)
    }

    /// Whether the step is behind: done or skipped.
    fn behind(&self, path: &str, step: &str) -> bool {
        self.ended(path, step)
            .is_some_and(|e| e.state != End::Failed)
    }

    /// The step with where it stands.
    fn step(&self, path: &'static str, step: &Step) -> Value {
        match (self.live.get(&(path, step.id)), self.ended(path, step.id)) {
            (Some(live), _) => step_data(
                step,
                "run",
                json!(if live.waiting { "waiting" } else { "running" }),
                live.progress.as_deref(),
                None,
            ),
            (None, Some(e)) => step_data(
                step,
                "run",
                json!(e.state),
                e.progress.as_deref(),
                e.result.as_deref(),
            ),
            (None, None) => step_data(step, "run", json!("pending"), None, None),
        }
    }

    /// The one question as the plan's first step, answered when the answer
    /// kept is the one the plan is drawn for.
    fn question(&self, path: &str) -> Value {
        let answered = self.kept.path.as_deref() == Some(path);
        question_data(answered)
    }
}

/// The one question as a step.
fn question_step() -> Step {
    Step {
        id: ROLE,
        title: journey::QUESTION.into(),
        what: String::new(),
        why: String::new(),
        action: Action::None,
        gate: Gate::Free,
        skippable: false,
        manual: Vec::new(),
        caution: None,
    }
}

fn question_data(answered: bool) -> Value {
    step_data(
        &question_step(),
        "choose_role",
        json!(if answered { "done" } else { "pending" }),
        None,
        None,
    )
}

/// A step that carries a caution starts only when the call names it again in
/// `confirm`, so a caller cannot start it without having read the caution.
fn confirmed(step: &Step, params: &Value) -> Result<(), Value> {
    let named = params.get("confirm").and_then(Value::as_str) == Some(step.id);
    if step.caution.is_some() && !named {
        return Err(error(REFUSED, NOT_CONFIRMED));
    }
    Ok(())
}

/// A step as a shell reads it. Every gate reads as free: a step the terminal
/// confirms by a typed word carries a caution, and a shell confirms it by the
/// button under that caution, which runs the step with `confirm` set to its
/// id. No step of this plan is a passkey ceremony, so
/// none has a purpose.
fn step_data(
    step: &Step,
    kind: &str,
    state: Value,
    progress: Option<&str>,
    result: Option<&str>,
) -> Value {
    json!({
        "id": step.id,
        "title": step.title,
        "what": step.what,
        "why": step.why,
        "kind": kind,
        "purpose": null,
        "gate": "free",
        "skippable": step.skippable,
        "caution": step.caution,
        "manual": step.manual,
        "command": step.command_line(),
        "state": state,
        "progress": progress,
        "result": result,
    })
}

/// What was found, one row a finding. A finding that needs action is one
/// setup takes care of when the plan has steps to run.
fn machine_rows(found: &[Finding], runnable: bool) -> Vec<Value> {
    found
        .iter()
        .map(|f| {
            json!({
                "id": f.label.to_lowercase().replace(' ', "_"),
                "label": f.label,
                "value": f.text,
                "ok": matches!(f.word, Word::Ok | Word::Watch),
                "fixable": f.word == Word::Action && runnable,
            })
        })
        .collect()
}

/// The answers on offer, each with whether this machine can take it.
fn roles(found: &Found) -> Vec<Value> {
    PATHS
        .iter()
        .map(|(id, path, role)| {
            let blocked = journey::plan(*path, &found.machine, &found.net, &found.opts).blocked;
            json!({
                "id": id,
                "label": path.label(),
                "what": path.blurb(),
                "stake_text": format!(
                    "from {}",
                    crate::rpc::format_tnzo(role.stake_minimum_wei())
                ),
                "eligible": blocked.is_none(),
                "reason": blocked.map(|b| b.what),
            })
        })
        .collect()
}

fn blocked_data(b: &Blocked) -> Value {
    json!({
        "what": b.what,
        "why": b.why,
        "fix": b.fix,
        "offers": b.offers.iter().filter_map(offer_name).collect::<Vec<_>>(),
    })
}

/// The name of a way out of a blocked plan. Switching to an answer setup
/// does not offer here has none.
fn offer_name(offer: &Offer) -> Option<&'static str> {
    match offer {
        Offer::SwitchTo(path) => PATHS.iter().find(|(_, p, _)| p == path).map(|(id, ..)| *id),
        Offer::Delegate => Some("delegate"),
        Offer::Finish => Some("finish"),
    }
}

/// The whole plan for `path` as a shell reads it.
fn plan_data(inner: &Inner, id: &'static str, path: Path, found: &Found) -> Value {
    let plan = journey::plan(path, &found.machine, &found.net, &found.opts);
    let mut steps = vec![inner.question(id)];
    steps.extend(plan.steps.iter().map(|s| inner.step(id, s)));
    json!({
        "path": id,
        "machine": machine_rows(
            &detect::findings(&found.machine, &found.net, &found.opts.rpc),
            plan.blocked.is_none(),
        ),
        "roles": roles(found),
        "steps": steps,
        "blocked": plan.blocked.as_ref().map(blocked_data),
        "next": plan.next,
    })
}

fn finish_first(title: &str) -> Value {
    error(REFUSED, &format!("Finish \"{title}\" first"))
}

fn step_named(params: &Value) -> Result<&str, Value> {
    params
        .get("step_id")
        .and_then(Value::as_str)
        .ok_or_else(|| error(INVALID_PARAMS, "step_id is needed"))
}

fn write(file: &std::path::Path, kept: &Kept) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let fresh = file.with_extension("tmp");
    std::fs::write(&fresh, serde_json::to_vec_pretty(kept)?)?;
    std::fs::rename(fresh, file)
}

/// What asking for a step found.
enum Turn {
    /// The step is behind or under way; this is how it stands.
    Settled(Value),
    /// It is the step's turn.
    Open {
        path: &'static str,
        step: Step,
        opts: Opts,
    },
}

/// Setup on one machine.
pub(crate) struct Setup {
    file: PathBuf,
    look: Look,
    inner: Mutex<Inner>,
}

impl Setup {
    /// Setup whose progress is kept in `file` and which sees the machine
    /// through `look`. A file that is missing or cannot be read as progress
    /// starts setup from its first step.
    pub(crate) fn new(file: PathBuf, look: Look) -> Arc<Self> {
        let kept = std::fs::read(&file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Arc::new(Self {
            file,
            look,
            inner: Mutex::new(Inner {
                kept,
                ..Inner::default()
            }),
        })
    }

    /// Setup of this machine, its progress kept beside the settings.
    pub(crate) fn here() -> Arc<Self> {
        Self::new(
            crate::config::config_path().with_file_name(PROGRESS_FILE),
            Box::new(look),
        )
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What was found on this machine: looked at again once what is known is
    /// old, and never while a step is under way.
    async fn found(&self) -> Arc<Found> {
        let known = {
            let inner = self.lock();
            inner
                .found
                .as_ref()
                .filter(|(at, _)| !inner.live.is_empty() || at.elapsed() < FOUND_KEPT)
                .map(|(_, found)| found.clone())
        };
        if let Some(found) = known {
            return found;
        }
        let found = Arc::new((self.look)().await);
        self.lock().found = Some((Instant::now(), found.clone()));
        found
    }

    fn keep(&self, kept: &Kept) {
        if let Err(e) = write(&self.file, kept) {
            eprintln!(
                "Could not keep setup's progress in {}: {e}",
                self.file.display()
            );
        }
    }

    /// `control_setupPlan`: the plan for the answer `params` names, else for
    /// the answer given, else for the first answer on offer. Naming an
    /// answer shows its plan and gives no answer.
    pub(crate) async fn plan(&self, params: &Value) -> Result<Value, Value> {
        let asked = match params.get("path") {
            None | Some(Value::Null) => None,
            Some(name) => Some(
                name.as_str()
                    .and_then(path_named)
                    .ok_or_else(|| error(INVALID_PARAMS, "path must be validate or operate"))?,
            ),
        };
        let found = self.found().await;
        let inner = self.lock();
        let (id, path) = asked
            .or_else(|| inner.chosen())
            .unwrap_or((PATHS[0].0, PATHS[0].1));
        Ok(plan_data(&inner, id, path, &found))
    }

    /// `control_setupRun`: answer the one question, or run the step whose
    /// turn it is. A step that is behind or under way is answered as it
    /// stands and nothing is run.
    pub(crate) async fn run(self: &Arc<Self>, params: &Value) -> Result<Value, Value> {
        let id = step_named(params)?;
        if id == ROLE {
            return self.answer(params);
        }
        match self.turn(id).await? {
            Turn::Settled(step) => Ok(step),
            Turn::Open { path, step, opts } => {
                confirmed(&step, params)?;
                self.start(path, &step, opts);
                Ok(self.lock().step(path, &step))
            }
        }
    }

    /// `control_setupSkip`: put a step that may be skipped behind. Skipping
    /// changes nothing on the machine, so it needs no confirmation.
    pub(crate) async fn skip(&self, params: &Value) -> Result<Value, Value> {
        let id = step_named(params)?;
        if id == ROLE {
            return Err(error(REFUSED, NOT_SKIPPABLE));
        }
        match self.turn(id).await? {
            Turn::Settled(step) => Ok(step),
            Turn::Open { path, step, .. } => {
                if !step.skippable {
                    return Err(error(REFUSED, NOT_SKIPPABLE));
                }
                self.end(path, step.id, End::Skipped, None, None);
                Ok(self.lock().step(path, &step))
            }
        }
    }

    /// Keep the answer to the one question. The answer already given changes
    /// nothing; another one moves setup to that answer's plan.
    fn answer(&self, params: &Value) -> Result<Value, Value> {
        let (id, _) = params
            .get("choice")
            .and_then(Value::as_str)
            .and_then(path_named)
            .ok_or_else(|| error(INVALID_PARAMS, "choice must be validate or operate"))?;
        let mut inner = self.lock();
        if inner.kept.path.as_deref() != Some(id) {
            inner.kept.path = Some(id.to_string());
            self.keep(&inner.kept);
        }
        Ok(question_data(true))
    }

    /// Find the step `id` in the plan of the answer given and say whether it
    /// is its turn: the steps go in the plan's order.
    async fn turn(&self, id: &str) -> Result<Turn, Value> {
        let found = self.found().await;
        let inner = self.lock();
        let (path_id, path) = inner
            .chosen()
            .ok_or_else(|| finish_first(journey::QUESTION))?;
        let plan = journey::plan(path, &found.machine, &found.net, &found.opts);
        if let Some(blocked) = &plan.blocked {
            return Err(error(REFUSED, &blocked.what));
        }
        let step = plan
            .steps
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| error(INVALID_PARAMS, "This plan has no such step"))?;
        if inner.behind(path_id, step.id) || inner.live.contains_key(&(path_id, step.id)) {
            return Ok(Turn::Settled(inner.step(path_id, step)));
        }
        let next = plan.steps.iter().find(|s| !inner.behind(path_id, s.id));
        if let Some(next) = next.filter(|next| next.id != step.id) {
            return Err(finish_first(&next.title));
        }
        Ok(Turn::Open {
            path: path_id,
            step: step.clone(),
            opts: found.opts.clone(),
        })
    }

    /// Start `step` unless it is behind or under way already. A step that
    /// ends at once is ended here; a command or a wait is followed to its
    /// end in the background.
    fn start(self: &Arc<Self>, path: &'static str, step: &Step, opts: Opts) {
        {
            let mut inner = self.lock();
            if inner.behind(path, step.id) || inner.live.contains_key(&(path, step.id)) {
                return;
            }
            inner.live.insert((path, step.id), Live::default());
        }
        match runner::begin(step, &opts) {
            Begun::Done(said) => self.end(path, step.id, End::Done, None, said),
            Begun::Failed(why) => self.end(path, step.id, End::Failed, Some(why), None),
            Begun::Running(running) => {
                let (me, step) = (self.clone(), step.clone());
                tokio::task::spawn_blocking(move || me.follow(path, &step, &running, &opts));
            }
            Begun::Waiting(url) => {
                let id = step.id;
                self.say(path, id, true, None);
                let me = self.clone();
                tokio::spawn(async move {
                    let heard = me.clone();
                    let answered = runner::wait_for_node(&url, move |attempt| {
                        heard.say(path, id, true, Some(runner::wait_message(attempt)));
                    })
                    .await;
                    if answered {
                        me.end(path, id, End::Done, None, None);
                    } else {
                        me.end(
                            path,
                            id,
                            End::Failed,
                            Some(runner::NODE_SILENT.into()),
                            None,
                        );
                    }
                });
            }
        }
    }

    /// Follow a step's command to its end, keeping what it prints the way
    /// the terminal does.
    fn follow(&self, path: &'static str, step: &Step, running: &Running, opts: &Opts) {
        let mut captured = Vec::new();
        let mut last = None;
        let mut code = None;
        while let Ok(msg) = running.rx.recv() {
            match msg {
                Msg::Line(line) => {
                    let line = line.trim_end().to_string();
                    if !line.trim().is_empty() {
                        last = Some(line.trim().to_string());
                        self.say(path, step.id, false, last.clone());
                    }
                    captured.push(line);
                }
                Msg::Exit(exit) => {
                    code = exit;
                    break;
                }
            }
        }
        match runner::finish(step, code, &captured, opts) {
            Ok(said) => self.end(path, step.id, End::Done, None, said),
            Err(why) => self.end(path, step.id, End::Failed, Some(why), last),
        }
    }

    /// Note what a step under way last said.
    fn say(&self, path: &'static str, id: &'static str, waiting: bool, progress: Option<String>) {
        if let Some(live) = self.lock().live.get_mut(&(path, id)) {
            live.waiting = waiting;
            live.progress = progress;
        }
    }

    /// Keep how a step ended. The machine is looked at again afterwards,
    /// since a step changes it.
    fn end(
        &self,
        path: &'static str,
        id: &'static str,
        state: End,
        result: Option<String>,
        progress: Option<String>,
    ) {
        let mut inner = self.lock();
        inner.live.remove(&(path, id));
        inner.found = None;
        inner
            .kept
            .steps
            .entry(path.to_string())
            .or_default()
            .insert(
                id.to_string(),
                Ended {
                    state,
                    result,
                    progress,
                },
            );
        self.keep(&inner.kept);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tui::detect::{KeyRoot, NodeBuild};

    /// A machine setup has something to do on: a hardware key that is ready
    /// and a node program that would start.
    fn machine(root: KeyRoot) -> Machine {
        let mut m = Machine::blank();
        m.root = root;
        m.node_binary = Some(PathBuf::from("/usr/bin/tenzro-node"));
        m.node_build = Some(NodeBuild {
            flavour: "cpu".into(),
            startup_ok: true,
            refusal: None,
        });
        m
    }

    fn found(root: KeyRoot, net: Net) -> Found {
        let machine = machine(root);
        let opts = Opts::defaults(&machine, crate::endpoint::PUBLIC_RPC);
        Found { machine, net, opts }
    }

    fn up() -> Net {
        Net::Reachable {
            chain_id: "0x1".into(),
        }
    }

    /// Setup that sees `found` and keeps its progress in `file`.
    pub(crate) fn seeing(file: PathBuf, found: Found) -> Arc<Setup> {
        Setup::new(
            file,
            Box::new(move || {
                let found = found.clone();
                Box::pin(async move { found })
            }),
        )
    }

    /// Setup on a ready machine with the network up.
    pub(crate) fn ready(file: PathBuf) -> Arc<Setup> {
        seeing(file, found(KeyRoot::TpmReady, up()))
    }

    fn reference(path: Path, f: &Found) -> journey::Plan {
        journey::plan(path, &f.machine, &f.net, &f.opts)
    }

    fn message(refusal: &Value) -> (i64, &str) {
        (
            refusal["code"].as_i64().unwrap(),
            refusal["message"].as_str().unwrap(),
        )
    }

    #[tokio::test]
    async fn the_plan_is_the_one_question_then_the_terminals_steps() {
        let dir = tempfile::tempdir().unwrap();
        let f = found(KeyRoot::TpmReady, up());
        let setup = seeing(dir.path().join("p.json"), f.clone());
        let plan = setup.plan(&Value::Null).await.unwrap();
        let terminal = reference(Path::Validate, &f);

        assert_eq!(plan["path"], "validate");
        assert_eq!(plan["blocked"], Value::Null);
        assert_eq!(plan["next"], terminal.next.as_str());
        let steps = plan["steps"].as_array().unwrap();
        assert_eq!(steps[0]["id"], "role");
        assert_eq!(steps[0]["title"], journey::QUESTION);
        assert_eq!(steps[0]["kind"], "choose_role");
        assert_eq!(steps[0]["state"], "pending");
        assert_eq!(steps.len(), terminal.steps.len() + 1);
        for (data, step) in steps[1..].iter().zip(&terminal.steps) {
            assert_eq!(data["id"], step.id);
            assert_eq!(data["title"], step.title.as_str());
            assert_eq!(data["what"], step.what.as_str());
            assert_eq!(data["why"], step.why.as_str());
            assert_eq!(data["kind"], "run");
            assert_eq!(data["gate"], "free");
            assert_eq!(data["skippable"], step.skippable);
            assert_eq!(data["caution"], json!(step.caution));
            assert_eq!(data["manual"], json!(step.manual));
            assert_eq!(data["command"], json!(step.command_line()));
            assert_eq!(data["state"], "pending");
            assert_eq!(data["progress"], Value::Null);
            assert_eq!(data["result"], Value::Null);
        }
    }

    #[tokio::test]
    async fn the_plan_says_what_was_found_and_which_answers_are_open() {
        let dir = tempfile::tempdir().unwrap();
        let f = found(KeyRoot::TpmReady, up());
        let setup = seeing(dir.path().join("p.json"), f.clone());
        let plan = setup.plan(&Value::Null).await.unwrap();

        let findings = detect::findings(&f.machine, &f.net, &f.opts.rpc);
        let rows = plan["machine"].as_array().unwrap();
        assert_eq!(rows.len(), findings.len());
        for (row, finding) in rows.iter().zip(&findings) {
            assert_eq!(row["label"], finding.label);
            assert_eq!(row["value"], finding.text.as_str());
        }
        let ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"hardware_key"), "{ids:?}");
        assert!(ids.contains(&"network"), "{ids:?}");

        let roles = plan["roles"].as_array().unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0]["id"], "validate");
        assert_eq!(roles[0]["label"], Path::Validate.label());
        assert_eq!(roles[0]["what"], Path::Validate.blurb());
        let from =
            |role: JoinRole| format!("from {}", crate::rpc::format_tnzo(role.stake_minimum_wei()));
        assert_eq!(roles[0]["stake_text"], from(JoinRole::Validator));
        assert_eq!(roles[0]["eligible"], true);
        assert_eq!(roles[0]["reason"], Value::Null);
        assert_eq!(roles[1]["id"], "operate");
        assert_eq!(roles[1]["label"], Path::Provide.label());
        assert_eq!(roles[1]["stake_text"], from(JoinRole::ModelProvider));
        assert_eq!(roles[1]["eligible"], true);
    }

    #[test]
    fn a_finding_that_needs_action_is_setups_to_fix_only_when_the_plan_runs() {
        let finding = |word| Finding {
            label: "Hardware key",
            word,
            text: "TPM 2.0".into(),
            fix: Vec::new(),
        };
        let rows = machine_rows(
            &[
                finding(Word::Ok),
                finding(Word::Watch),
                finding(Word::Action),
                finding(Word::Down),
            ],
            true,
        );
        let read = |i: usize| (rows[i]["ok"] == true, rows[i]["fixable"] == true);
        assert_eq!(rows[0]["id"], "hardware_key");
        assert_eq!(read(0), (true, false));
        assert_eq!(read(1), (true, false));
        assert_eq!(read(2), (false, true));
        assert_eq!(read(3), (false, false));
        let blocked = machine_rows(&[finding(Word::Action)], false);
        assert_eq!(blocked[0]["fixable"], false);
    }

    #[test]
    fn a_step_confirmed_by_a_typed_word_carries_a_caution() {
        let mut typed = 0;
        for root in [KeyRoot::TpmReady, KeyRoot::TpmNeedsProvision] {
            for delegated in [false, true] {
                let mut f = found(root.clone(), up());
                f.opts.delegated = delegated;
                for (_, path, _) in PATHS {
                    for step in reference(path, &f).steps {
                        if matches!(step.gate, Gate::Typed(_)) {
                            typed += 1;
                            assert!(step.caution.is_some(), "{} has no caution", step.id);
                        }
                    }
                }
            }
        }
        assert!(typed > 0, "no plan had a step confirmed by a word");
    }

    #[test]
    fn a_step_with_a_caution_needs_its_own_name_to_start() {
        let f = found(KeyRoot::TpmNeedsProvision, up());
        let steps = reference(Path::Validate, &f).steps;
        let cautioned = steps.iter().find(|s| s.caution.is_some()).unwrap();
        let plain = steps.iter().find(|s| s.caution.is_none()).unwrap();
        for asked in [
            json!({ "step_id": cautioned.id }),
            json!({ "step_id": cautioned.id, "confirm": "yes" }),
            json!({ "step_id": cautioned.id, "confirm": plain.id }),
            json!({ "step_id": cautioned.id, "confirm": true }),
        ] {
            let refusal = confirmed(cautioned, &asked).unwrap_err();
            assert_eq!(message(&refusal), (REFUSED, NOT_CONFIRMED), "{asked}");
        }
        let named = json!({ "step_id": cautioned.id, "confirm": cautioned.id });
        assert!(confirmed(cautioned, &named).is_ok());
        assert!(confirmed(plain, &json!({ "step_id": plain.id })).is_ok());
    }

    #[tokio::test]
    async fn a_step_with_a_caution_is_not_started_unconfirmed() {
        let dir = tempfile::tempdir().unwrap();
        let f = found(KeyRoot::TpmNeedsProvision, up());
        let steps = reference(Path::Validate, &f).steps;
        let setup = seeing(dir.path().join("p.json"), f);
        setup
            .run(&json!({"step_id": "role", "choice": "validate"}))
            .await
            .unwrap();
        // Bring the cautioned step's turn without running any program.
        let at = steps.iter().position(|s| s.caution.is_some()).unwrap();
        for step in &steps[..at] {
            let asked = json!({ "step_id": step.id });
            if step.skippable {
                setup.skip(&asked).await.unwrap();
            } else {
                assert!(!matches!(step.action, Action::Exec { .. }), "{}", step.id);
                assert_eq!(setup.run(&asked).await.unwrap()["state"], "done");
            }
        }

        let cautioned = steps[at].id;
        let refusal = setup
            .run(&json!({ "step_id": cautioned }))
            .await
            .unwrap_err();
        assert_eq!(message(&refusal), (REFUSED, NOT_CONFIRMED));
        let plan = setup.plan(&Value::Null).await.unwrap();
        let kept = plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == cautioned)
            .unwrap();
        assert_eq!(kept["state"], "pending", "{kept}");
    }

    #[tokio::test]
    async fn a_blocked_plan_says_why_and_what_is_offered() {
        let dir = tempfile::tempdir().unwrap();
        let f = found(KeyRoot::TpmReady, Net::NotResolving);
        let setup = seeing(dir.path().join("p.json"), f.clone());
        let blocked = reference(Path::Validate, &f)
            .blocked
            .expect("a network that does not resolve blocks setup");

        let plan = setup.plan(&Value::Null).await.unwrap();
        assert_eq!(plan["blocked"]["what"], blocked.what.as_str());
        assert_eq!(plan["blocked"]["why"], blocked.why.as_str());
        assert_eq!(plan["blocked"]["fix"], json!(blocked.fix));
        for offer in plan["blocked"]["offers"].as_array().unwrap() {
            assert!(
                ["validate", "operate", "delegate", "finish"].contains(&offer.as_str().unwrap()),
                "{offer}"
            );
        }
        assert_eq!(plan["roles"][0]["eligible"], false);
        assert_eq!(plan["roles"][0]["reason"], blocked.what.as_str());

        setup
            .run(&json!({"step_id": "role", "choice": "validate"}))
            .await
            .unwrap();
        let refusal = setup
            .run(&json!({"step_id": "hardware"}))
            .await
            .unwrap_err();
        assert_eq!(message(&refusal), (REFUSED, blocked.what.as_str()));
    }

    #[test]
    fn only_the_answers_on_offer_are_named_as_ways_out() {
        assert_eq!(offer_name(&Offer::SwitchTo(Path::Provide)), Some("operate"));
        assert_eq!(
            offer_name(&Offer::SwitchTo(Path::Validate)),
            Some("validate")
        );
        assert_eq!(offer_name(&Offer::SwitchTo(Path::Local)), None);
        assert_eq!(offer_name(&Offer::Delegate), Some("delegate"));
        assert_eq!(offer_name(&Offer::Finish), Some("finish"));
    }

    #[tokio::test]
    async fn naming_an_answer_shows_its_plan_and_gives_no_answer() {
        let dir = tempfile::tempdir().unwrap();
        let setup = ready(dir.path().join("p.json"));

        let shown = setup.plan(&json!({"path": "operate"})).await.unwrap();
        assert_eq!(shown["path"], "operate");
        assert_eq!(shown["steps"][0]["state"], "pending");
        let refusal = setup.plan(&json!({"path": "local"})).await.unwrap_err();
        assert_eq!(
            message(&refusal),
            (INVALID_PARAMS, "path must be validate or operate")
        );
        assert_eq!(
            setup.plan(&Value::Null).await.unwrap()["steps"][0]["state"],
            "pending"
        );

        let refusal = setup
            .run(&json!({"step_id": "role", "choice": "local"}))
            .await
            .unwrap_err();
        assert_eq!(
            message(&refusal),
            (INVALID_PARAMS, "choice must be validate or operate")
        );
        let answered = setup
            .run(&json!({"step_id": "role", "choice": "operate"}))
            .await
            .unwrap();
        assert_eq!(answered["state"], "done");
        let plan = setup.plan(&Value::Null).await.unwrap();
        assert_eq!(plan["path"], "operate");
        assert_eq!(plan["steps"][0]["state"], "done");
        let other = setup.plan(&json!({"path": "validate"})).await.unwrap();
        assert_eq!(other["steps"][0]["state"], "pending");
    }

    #[tokio::test]
    async fn steps_go_in_order_and_a_done_step_run_again_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("p.json");
        let setup = ready(file.clone());

        let refusal = setup
            .run(&json!({"step_id": "hardware"}))
            .await
            .unwrap_err();
        assert_eq!(
            message(&refusal),
            (REFUSED, "Finish \"What do you want to do?\" first")
        );
        setup
            .run(&json!({"step_id": "role", "choice": "validate"}))
            .await
            .unwrap();

        let refusal = setup.run(&json!({"step_id": "leave"})).await.unwrap_err();
        assert_eq!(
            message(&refusal),
            (REFUSED, "Finish \"This machine\" first")
        );
        let refusal = setup.run(&json!({"step_id": "nothing"})).await.unwrap_err();
        assert_eq!(refusal["code"], INVALID_PARAMS);
        let refusal = setup.run(&json!({})).await.unwrap_err();
        assert_eq!(refusal["code"], INVALID_PARAMS);
        let refusal = setup
            .skip(&json!({"step_id": "hardware"}))
            .await
            .unwrap_err();
        assert_eq!(message(&refusal), (REFUSED, NOT_SKIPPABLE));
        let refusal = setup.skip(&json!({"step_id": "role"})).await.unwrap_err();
        assert_eq!(message(&refusal), (REFUSED, NOT_SKIPPABLE));

        let done = setup.run(&json!({"step_id": "hardware"})).await.unwrap();
        assert_eq!(done["state"], "done");
        let kept = std::fs::read(&file).unwrap();
        let again = setup.run(&json!({"step_id": "hardware"})).await.unwrap();
        assert_eq!(again, done);
        assert_eq!(std::fs::read(&file).unwrap(), kept);
        assert_eq!(
            setup.skip(&json!({"step_id": "hardware"})).await.unwrap(),
            done
        );
    }

    #[tokio::test]
    async fn setup_picks_up_where_it_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kept").join("p.json");
        {
            let setup = ready(file.clone());
            setup
                .run(&json!({"step_id": "role", "choice": "validate"}))
                .await
                .unwrap();
            setup.run(&json!({"step_id": "hardware"})).await.unwrap();
        }
        let plan = ready(file.clone()).plan(&Value::Null).await.unwrap();
        assert_eq!(plan["path"], "validate");
        assert_eq!(plan["steps"][0]["state"], "done");
        assert_eq!(plan["steps"][1]["id"], "hardware");
        assert_eq!(plan["steps"][1]["state"], "done");
        assert_eq!(plan["steps"][2]["state"], "pending");
        // The other answer's plan has its own steps to do.
        let other = ready(file.clone())
            .plan(&json!({"path": "operate"}))
            .await
            .unwrap();
        assert_eq!(other["steps"][1]["state"], "pending");

        std::fs::write(&file, b"not progress").unwrap();
        let fresh = ready(file).plan(&Value::Null).await.unwrap();
        assert_eq!(fresh["steps"][0]["state"], "pending");
        assert_eq!(fresh["steps"][1]["state"], "pending");
    }

    #[cfg(unix)]
    mod running {
        use super::*;
        use crate::tui::journey::Prog;

        fn shell(id: &'static str, script: &str, save_as: Option<&'static str>) -> Step {
            Step {
                action: Action::Exec {
                    prog: Prog::Other("sh"),
                    args: vec!["-c".into(), script.into()],
                    detached: false,
                    save_as,
                },
                id,
                ..question_step()
            }
        }

        /// The step once it ended, having been seen in each state `seen`
        /// collects on the way.
        async fn ended(setup: &Setup, step: &Step, seen: &mut Vec<Value>) -> Value {
            for _ in 0..600 {
                let data = setup.lock().step("validate", step);
                if !["running", "waiting"].contains(&data["state"].as_str().unwrap()) {
                    return data;
                }
                if seen.last() != Some(&data) {
                    seen.push(data);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("the step did not end");
        }

        fn opts_in(dir: &std::path::Path) -> Opts {
            let mut opts = found(KeyRoot::TpmReady, up()).opts;
            opts.data_dir = dir.to_path_buf();
            opts
        }

        #[tokio::test]
        async fn a_command_is_followed_to_its_end() {
            let dir = tempfile::tempdir().unwrap();
            let setup = ready(dir.path().join("p.json"));
            let step = shell("t", "echo first; sleep 2; echo last", None);
            setup.start("validate", &step, opts_in(dir.path()));

            let mut seen = Vec::new();
            let end = ended(&setup, &step, &mut seen).await;
            assert!(
                seen.iter()
                    .any(|s| s["state"] == "running" && s["progress"] == "first"),
                "{seen:?}"
            );
            assert_eq!(end["state"], "done");
            assert_eq!(end["result"], Value::Null);
            // Started again, a done step runs nothing.
            setup.start("validate", &step, opts_in(dir.path()));
            assert_eq!(setup.lock().step("validate", &step), end);
        }

        #[tokio::test]
        async fn a_command_that_fails_says_why_and_can_be_run_again() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("p.json");
            let setup = ready(file.clone());
            let marker = dir.path().join("second-time");
            let script = format!(
                "if [ -e {0} ]; then echo fine; else touch {0}; echo broke; exit 3; fi",
                marker.display()
            );
            let step = shell("t", &script, None);

            setup.start("validate", &step, opts_in(dir.path()));
            let end = ended(&setup, &step, &mut Vec::new()).await;
            assert_eq!(end["state"], "failed");
            assert_eq!(end["result"], "it stopped with exit code 3");
            assert_eq!(end["progress"], "broke");
            // A failed step is kept as failed, and is not behind.
            assert_eq!(
                ready(file).lock().step("validate", &step)["state"],
                "failed"
            );

            setup.start("validate", &step, opts_in(dir.path()));
            let end = ended(&setup, &step, &mut Vec::new()).await;
            assert_eq!(end["state"], "done");
            assert_eq!(end["result"], Value::Null);
        }

        #[tokio::test]
        async fn a_step_that_keeps_its_output_keeps_it_as_the_terminal_does() {
            let dir = tempfile::tempdir().unwrap();
            let setup = ready(dir.path().join("p.json"));
            let step = shell("t", "echo one; echo two", Some("list.txt"));
            setup.start("validate", &step, opts_in(dir.path()));
            let end = ended(&setup, &step, &mut Vec::new()).await;
            assert_eq!(end["state"], "done");
            let list = dir.path().join("list.txt");
            assert_eq!(std::fs::read_to_string(&list).unwrap(), "one\ntwo");
            assert_eq!(
                end["progress"],
                format!("Kept the list in {}", list.display())
            );
        }

        #[tokio::test]
        async fn a_program_that_is_missing_fails_the_step_at_once() {
            let dir = tempfile::tempdir().unwrap();
            let setup = ready(dir.path().join("p.json"));
            let mut step = shell("t", "", None);
            step.action = Action::Exec {
                prog: Prog::Other("definitely-not-a-program-xyz"),
                args: Vec::new(),
                detached: false,
                save_as: None,
            };
            setup.start("validate", &step, opts_in(dir.path()));
            let data = setup.lock().step("validate", &step);
            assert_eq!(data["state"], "failed");
            assert!(
                data["result"].as_str().unwrap().contains("was not found"),
                "{data}"
            );
        }

        #[tokio::test]
        async fn a_wait_ends_when_the_node_answers() {
            let node = crate::rpc::nonce_and_chain_id_tests::node_answering(&[(
                "eth_chainId",
                r#""0x3444""#,
            )])
            .await;
            let dir = tempfile::tempdir().unwrap();
            let setup = ready(dir.path().join("p.json"));
            let mut step = shell("t", "", None);
            step.action = Action::WaitRpc { url: node };
            setup.start("validate", &step, opts_in(dir.path()));

            let mut seen = Vec::new();
            let end = ended(&setup, &step, &mut seen).await;
            assert!(seen.iter().all(|s| s["state"] == "waiting"), "{seen:?}");
            assert_eq!(end["state"], "done");
        }
    }
}
