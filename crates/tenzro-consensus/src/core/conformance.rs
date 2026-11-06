//! Replays executions of the commit rule specification
//! (`spec/commit_rule.qnt`) through the core, step by step, and checks after
//! every step that each honest validator's core holds the state the
//! specification gives it.
//!
//! Executions are ITF traces (`quint run --mbt --out-itf`), plain or gzipped,
//! from the instances that decide eagerly (`EAGER = true`), as the core does.
//! A file's name starts with `n<N>f<F>_`, the committee size and the number
//! of Byzantine validators of its instance.
//!
//! The replay is the network and the Byzantine validators; each honest
//! validator is a real [`Core`]:
//!
//! - `Propose(v)`: the author's core proposes the round ([`Core::propose`]).
//!   Every vertex an honest core proposes, here or by catching up, must
//!   reference strongly and weakly exactly what the specification's does.
//! - `Build(v)`: a Byzantine vertex with the specification's references.
//! - `First((i, v))`: core `i` receives `v` as its author's proposal.
//! - `Deliver((i, v))`: reliable broadcast delivers `v` at core `i`: readies
//!   from the other validators, then the body if `i` lacks it.
//! - `Restart(i)`: core `i` is rebuilt from everything it journaled
//!   ([`Core::recover`]).
//!
//! After every step each core progresses ([`Core::progress`]) until nothing
//! changes, as it would on its next input; the specification's eager
//! instances do the same.
//!
//! Compared after every step, per honest validator: the delivered vertices
//! (`view`), the first proposals (`fp`), the decided slots (`log`), the
//! released vertices (`ordered`), the first undecided slot (`nextSlot`), the
//! last round proposed (`proposed`) and the longest released sequence
//! (`executed`); and once, the leader table (`leaders`).
//!
//! `COMMIT_RULE_TRACES` names the folder of traces; without it the replay
//! does nothing. `CONFORMANCE_REPORT` names a file the summary, the count
//! per instance and every divergence are written to. Executions replay on
//! `CONFORMANCE_THREADS` threads (default 1) in one pool with the checkpoint
//! votes' (`conformance_replay`), taking every instance of both in turn;
//! with `CONFORMANCE_DEADLINE` (Unix seconds) no replay starts after it, and
//! the executions left are counted as not replayed.

use super::*;
use crate::config::{ConsensusConfig, TimeRules};
use crate::harness::tdc::{committee, genesis_start};
use crate::rbc::SignalKind;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// A vertex of the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct VId {
    round: Round,
    author: ValidatorIndex,
    ver: u64,
}

/// A slot decision of the specification: the committed vertex, or none for
/// a skip.
type Entry = ((Round, usize), Option<VId>);

#[derive(Debug, Clone)]
enum Step {
    Init,
    Propose(VId),
    Build(VId),
    First(ValidatorIndex, VId),
    Deliver(ValidatorIndex, VId),
    Decide(ValidatorIndex),
    Restart(ValidatorIndex),
}

impl Step {
    fn name(&self) -> &'static str {
        match self {
            Step::Init => "init",
            Step::Propose(_) => "propose",
            Step::Build(_) => "build",
            Step::First(..) => "first",
            Step::Deliver(..) => "deliver",
            Step::Decide(_) => "decide",
            Step::Restart(_) => "restart",
        }
    }
}

/// One state of an execution, the variables the replay maps.
struct State {
    step: Step,
    created: BTreeMap<VId, BTreeSet<VId>>,
    weak: BTreeMap<VId, BTreeSet<VId>>,
    view: BTreeMap<ValidatorIndex, BTreeSet<VId>>,
    fp: BTreeMap<ValidatorIndex, BTreeMap<(Round, ValidatorIndex), BTreeSet<VId>>>,
    log: BTreeMap<ValidatorIndex, Vec<Entry>>,
    ordered: BTreeMap<ValidatorIndex, Vec<VId>>,
    next_slot: BTreeMap<ValidatorIndex, (Round, usize)>,
    proposed: BTreeMap<ValidatorIndex, i64>,
    executed: BTreeMap<ValidatorIndex, Vec<VId>>,
    leaders: BTreeMap<Round, Vec<ValidatorIndex>>,
}

// ---------------------------------------------------------------------------
// ITF values.
// ---------------------------------------------------------------------------

fn int(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n.as_i64().expect("integer"),
        Value::Object(o) => o
            .get("#bigint")
            .and_then(Value::as_str)
            .expect("#bigint")
            .parse()
            .expect("integer"),
        _ => panic!("not an integer: {v}"),
    }
}

fn items<'a>(v: &'a Value, tag: &str) -> &'a [Value] {
    v.get(tag)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("not a {tag}: {v}"))
}

fn tup(v: &Value) -> &[Value] {
    items(v, "#tup")
}

fn set(v: &Value) -> &[Value] {
    items(v, "#set")
}

fn map(v: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    items(v, "#map").iter().map(|kv| {
        let kv = kv.as_array().expect("map entry");
        (&kv[0], &kv[1])
    })
}

fn list(v: &Value) -> &[Value] {
    v.as_array().unwrap_or_else(|| panic!("not a list: {v}"))
}

fn vid(v: &Value) -> VId {
    VId {
        round: int(&v["round"]) as Round,
        author: int(&v["author"]) as ValidatorIndex,
        ver: int(&v["ver"]) as u64,
    }
}

fn vids(v: &Value) -> BTreeSet<VId> {
    set(v).iter().map(vid).collect()
}

fn slot(v: &Value) -> (Round, usize) {
    let t = tup(v);
    (int(&t[0]) as Round, int(&t[1]) as usize)
}

fn tag(v: &Value) -> (&str, &Value) {
    (v["tag"].as_str().expect("variant tag"), &v["value"])
}

fn per_validator<T>(v: &Value, f: impl Fn(&Value) -> T) -> BTreeMap<ValidatorIndex, T> {
    map(v)
        .map(|(k, x)| (int(k) as ValidatorIndex, f(x)))
        .collect()
}

fn state(raw: &Value) -> State {
    let obj = raw.as_object().expect("state");
    let var = |name: &str| -> &Value {
        obj.iter()
            .find(|(k, _)| *k == name || k.ends_with(&format!("::{name}")))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("no variable {name}"))
    };
    let step = {
        let (t, x) = tag(var("lastStep"));
        match t {
            "Init" => Step::Init,
            "Propose" => Step::Propose(vid(x)),
            "Build" => Step::Build(vid(x)),
            "First" => {
                let p = tup(x);
                Step::First(int(&p[0]) as ValidatorIndex, vid(&p[1]))
            }
            "Deliver" => {
                let p = tup(x);
                Step::Deliver(int(&p[0]) as ValidatorIndex, vid(&p[1]))
            }
            "Decide" => Step::Decide(int(x) as ValidatorIndex),
            "Restart" => Step::Restart(int(x) as ValidatorIndex),
            "FastForward" => {
                panic!("a checkpoint fast-forward: replay only instances without FAST_FORWARD")
            }
            other => panic!("unknown step {other}"),
        }
    };
    State {
        step,
        created: map(var("created"))
            .map(|(k, x)| (vid(k), vids(x)))
            .collect(),
        weak: map(var("weak")).map(|(k, x)| (vid(k), vids(x))).collect(),
        view: per_validator(var("view"), vids),
        fp: per_validator(var("fp"), |m| {
            map(m)
                .map(|(k, x)| {
                    let t = tup(k);
                    ((int(&t[0]) as Round, int(&t[1]) as ValidatorIndex), vids(x))
                })
                .collect()
        }),
        log: per_validator(var("log"), |l| {
            list(l)
                .iter()
                .map(|e| {
                    let t = tup(e);
                    let d = match tag(&t[1]) {
                        ("Commit", x) => Some(vid(x)),
                        ("Skip", _) => None,
                        (other, _) => panic!("undecided slot in a log: {other}"),
                    };
                    (slot(&t[0]), d)
                })
                .collect()
        }),
        ordered: per_validator(var("ordered"), |l| list(l).iter().map(vid).collect()),
        next_slot: per_validator(var("nextSlot"), slot),
        proposed: per_validator(var("proposed"), int),
        executed: per_validator(var("executed"), |l| list(l).iter().map(vid).collect()),
        leaders: map(var("leaders"))
            .map(|(k, x)| {
                (
                    int(k) as Round,
                    list(x).iter().map(|a| int(a) as ValidatorIndex).collect(),
                )
            })
            .collect(),
    }
}

fn load(path: &Path) -> Vec<State> {
    let mut text = String::new();
    let f = std::fs::File::open(path).expect("trace file");
    if path.extension().is_some_and(|e| e == "gz") {
        flate2::read::GzDecoder::new(f)
            .read_to_string(&mut text)
            .expect("gzipped trace");
    } else {
        std::io::BufReader::new(f)
            .read_to_string(&mut text)
            .expect("trace");
    }
    let v: Value = serde_json::from_str(&text).expect("ITF json");
    list(&v["states"]).iter().map(state).collect()
}

/// `n<N>f<F>_...`: the instance's committee size and Byzantine validators.
fn instance(path: &Path) -> (usize, usize) {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let head = name.split('_').next().unwrap_or("");
    let (n, f) = head
        .strip_prefix('n')
        .and_then(|r| r.split_once('f'))
        .unwrap_or_else(|| panic!("trace name {name} does not start with n<N>f<F>_"));
    (n.parse().expect("N"), f.parse().expect("F"))
}

// ---------------------------------------------------------------------------
// The replay.
// ---------------------------------------------------------------------------

/// Where a replay left the specification.
#[derive(Debug)]
struct Divergence {
    step: usize,
    action: String,
    validator: Option<ValidatorIndex>,
    variable: &'static str,
    spec: String,
    core: String,
}

#[derive(Debug, Default, Clone)]
struct Tally {
    traces: usize,
    steps: usize,
    actions: BTreeMap<&'static str, usize>,
    commits: usize,
    skips: usize,
}

impl Tally {
    fn add(&mut self, o: &Tally) {
        self.traces += o.traces;
        self.steps += o.steps;
        for (k, v) in &o.actions {
            *self.actions.entry(k).or_default() += v;
        }
        self.commits += o.commits;
        self.skips += o.skips;
    }
}

const NOW: u64 = 0;

struct Replay {
    n: usize,
    honest: Vec<ValidatorIndex>,
    committee: Committee,
    cfg: CoreConfig,
    start: EpochStart,
    cores: BTreeMap<ValidatorIndex, Core>,
    journals: BTreeMap<ValidatorIndex, Vec<Record>>,
    vertices: BTreeMap<VId, Vertex>,
    names: HashMap<Digest, VId>,
    executed: BTreeMap<ValidatorIndex, Vec<VId>>,
    checked: BTreeSet<VId>,
    /// Vertices an honest core proposed by itself, in a step that is not the
    /// specification's `Propose` of them, which the specification creates
    /// later (see [`Replay::apply`]).
    early: BTreeSet<VId>,
    tally: Tally,
}

fn show<T: std::fmt::Debug>(x: &T) -> String {
    format!("{x:?}")
}

impl Replay {
    fn new(n: usize, f: usize) -> Self {
        let (committee, _) = committee(n, n as u64);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &TimeRules::default());
        let start = genesis_start();
        let honest: Vec<ValidatorIndex> = (0..(n - f) as ValidatorIndex).collect();
        let cores = honest
            .iter()
            .map(|&i| {
                (
                    i,
                    Core::new(cfg.clone(), committee.clone(), i, start.clone()),
                )
            })
            .collect();
        Self {
            n,
            honest: honest.clone(),
            committee,
            cfg,
            start,
            cores,
            journals: honest.iter().map(|&i| (i, Vec::new())).collect(),
            vertices: BTreeMap::new(),
            names: HashMap::new(),
            executed: honest.iter().map(|&i| (i, Vec::new())).collect(),
            checked: BTreeSet::new(),
            early: BTreeSet::new(),
            tally: Tally::default(),
        }
    }

    fn name(&mut self, id: VId, v: Vertex) -> Result<(), String> {
        let d = v.digest();
        if let Some(old) = self.vertices.get(&id) {
            if old.digest() != d {
                return Err(format!("{id:?} is two different vertices"));
            }
            return Ok(());
        }
        self.names.insert(d, id);
        self.vertices.insert(id, v);
        Ok(())
    }

    fn named(&self, r: &VertexRef) -> Result<VId, String> {
        self.names
            .get(&r.digest)
            .copied()
            .ok_or_else(|| format!("unknown vertex ({}, {})", r.round, r.source))
    }

    fn reference(&self, id: &VId) -> VertexRef {
        let v = &self.vertices[id];
        v.reference()
    }

    /// Takes every core's output: its own proposals are named, its journal
    /// kept for a restart, the rest dropped (the replay is the network).
    fn drain(&mut self) -> Result<(), String> {
        let mut own = Vec::new();
        for (&i, core) in self.cores.iter_mut() {
            for (_, m) in core.take_outbox() {
                if let Message::Propose(v) = m
                    && v.source == i
                {
                    own.push(v);
                }
            }
            core.take_events();
            self.journals
                .get_mut(&i)
                .expect("journal")
                .extend(core.take_journal());
        }
        for v in own {
            let id = VId {
                round: v.round,
                author: v.source,
                ver: 0,
            };
            self.name(id, v)?;
        }
        Ok(())
    }

    fn byzantine_vertex(&self, id: VId, refs: &BTreeSet<VId>) -> Vertex {
        let mut strong: Vec<VertexRef> = refs.iter().map(|r| self.reference(r)).collect();
        strong.sort();
        Vertex {
            epoch: self.committee.epoch,
            round: id.round,
            source: id.author,
            strong,
            weak: Vec::new(),
            batches: Vec::new(),
            carried: Vec::new(),
            timestamp_ms: id.ver,
        }
    }

    fn ready(round: Round, source: ValidatorIndex, digest: Digest) -> Message {
        Message::Signals(vec![Signal {
            kind: SignalKind::Ready,
            round,
            source,
            digest,
        }])
    }

    /// Reliable broadcast delivers `id` at `i`: readies from the other
    /// validators until it delivers, then the body if `i` lacks it.
    fn deliver(&mut self, i: ValidatorIndex, id: VId) {
        let v = self.vertices[&id].clone();
        let d = v.digest();
        let others: Vec<ValidatorIndex> =
            (0..self.n as ValidatorIndex).filter(|&j| j != i).collect();
        for j in others {
            let core = self.cores.get_mut(&i).expect("core");
            if core.rbc.delivered(v.round, v.source).is_some() {
                break;
            }
            core.on_messages(j, vec![Self::ready(v.round, v.source, d)], NOW);
        }
        let core = self.cores.get_mut(&i).expect("core");
        if !core.dag.contains(&d) {
            let from = if v.source != i {
                v.source
            } else {
                ((i as usize + 1) % self.n) as ValidatorIndex
            };
            core.on_messages(from, vec![Message::Vertices(vec![v])], NOW);
        }
    }

    fn apply(&mut self, step: &Step, post: &State) -> Result<(), Divergence> {
        let fail = |variable: &'static str, validator, spec: String, core: String| Divergence {
            step: 0,
            action: format!("{step:?}"),
            validator,
            variable,
            spec,
            core,
        };
        let internal = |e: String| fail("replay", None, String::new(), e);
        match step {
            Step::Init => {}
            Step::Propose(id) => {
                let a = id.author;
                let core = self
                    .cores
                    .get_mut(&a)
                    .ok_or_else(|| internal("Byzantine proposer".into()))?;
                if id.round > 0 && core.round_weight(id.round - 1) < core.committee.quorum() {
                    return Err(fail(
                        "propose",
                        Some(a),
                        format!("proposes round {}", id.round),
                        "holds no quorum of the round before".into(),
                    ));
                }
                // A core that jumped to this round itself, while delivering,
                // has proposed it already: the specification creates the
                // vertex now, and the references are compared below.
                if !self.early.remove(id) {
                    core.propose(id.round, NOW);
                }
                self.drain().map_err(internal)?;
                if !self.vertices.contains_key(id) {
                    return Err(internal(format!("{id:?} was not proposed")));
                }
            }
            Step::Build(id) => {
                let refs = post
                    .created
                    .get(id)
                    .ok_or_else(|| internal(format!("{id:?} not created")))?;
                let v = self.byzantine_vertex(*id, refs);
                self.name(*id, v).map_err(internal)?;
            }
            Step::First(i, id) => {
                let v = self.vertices[id].clone();
                let core = self
                    .cores
                    .get_mut(i)
                    .ok_or_else(|| internal("Byzantine receiver".into()))?;
                core.on_messages(id.author, vec![Message::Propose(v)], NOW);
            }
            Step::Deliver(i, id) => {
                self.deliver(*i, *id);
            }
            Step::Decide(i) => {
                return Err(internal(format!(
                    "a lazy decision by {i}: replay only instances with EAGER = true"
                )));
            }
            Step::Restart(i) => {
                let records = self.journals[i].clone();
                let core = Core::recover(
                    self.cfg.clone(),
                    self.committee.clone(),
                    *i,
                    self.start.clone(),
                    records,
                    0,
                    NOW,
                );
                self.cores.insert(*i, core);
            }
        }
        // The core progresses on every input it receives; the specification
        // takes it to where nothing more changes before the next step.
        for core in self.cores.values_mut() {
            for _ in 0..3 {
                core.progress(NOW);
            }
        }
        self.drain().map_err(internal)?;
        // The core proposes a round by itself, without waiting for a
        // `Propose` step, when it holds a quorum of a round above its own and
        // leads a slot of it (`Core::try_advance`); the specification takes
        // that proposal as its own `Propose` action, a step later. Such a
        // vertex is deferred until the specification creates it, and the
        // specification must do so by `Propose` of exactly that vertex.
        if !matches!(step, Step::Propose(_)) {
            for id in self.vertices.keys() {
                if self.honest.contains(&id.author)
                    && !self.checked.contains(id)
                    && !post.created.contains_key(id)
                {
                    self.early.insert(*id);
                }
            }
        }
        Ok(())
    }

    fn compare(&mut self, s: &State) -> Result<(), Divergence> {
        let fail =
            |variable: &'static str, i: ValidatorIndex, spec: String, core: String| Divergence {
                step: 0,
                action: format!("{:?}", s.step),
                validator: Some(i),
                variable,
                spec,
                core,
            };
        let internal = |i, e: String| fail("replay", i, String::new(), e);
        // Every vertex an honest core proposed, by the replay's call or by
        // catching up, references what the specification's vertex does.
        let fresh: Vec<VId> = self
            .vertices
            .keys()
            .filter(|id| {
                self.honest.contains(&id.author)
                    && !self.checked.contains(*id)
                    && !self.early.contains(*id)
            })
            .copied()
            .collect();
        for id in fresh {
            let v = &self.vertices[&id];
            let names = |refs: &[VertexRef]| -> Result<BTreeSet<VId>, String> {
                refs.iter().map(|r| self.named(r)).collect()
            };
            let strong = names(&v.strong).map_err(|e| internal(id.author, e))?;
            let weak = names(&v.weak).map_err(|e| internal(id.author, e))?;
            let want = s.created.get(&id).cloned();
            if want.as_ref() != Some(&strong) {
                return Err(fail(
                    "created",
                    id.author,
                    format!("{id:?}: {want:?}"),
                    show(&strong),
                ));
            }
            let want = s.weak.get(&id).cloned().unwrap_or_default();
            if want != weak {
                return Err(fail(
                    "weak",
                    id.author,
                    format!("{id:?}: {want:?}"),
                    show(&weak),
                ));
            }
            self.checked.insert(id);
        }
        // A deferred vertex the specification created by another step than
        // its `Propose`, or one it never creates, is a divergence.
        if let Some(id) = self.early.iter().find(|id| s.created.contains_key(id)) {
            return Err(fail(
                "created",
                id.author,
                format!("{id:?} created by {:?}", s.step),
                "the core proposed it by itself, before the specification's Propose".into(),
            ));
        }
        let waiting: BTreeSet<ValidatorIndex> = self.early.iter().map(|id| id.author).collect();
        for &i in &self.honest {
            let core = &self.cores[&i];

            let top = core.dag.highest_round().unwrap_or(0);
            let mut view = BTreeSet::new();
            for r in core.dag.floor()..=top {
                for (src, d, _) in core.dag.round(r) {
                    view.insert(
                        self.named(&VertexRef {
                            round: r,
                            source: src,
                            digest: *d,
                        })
                        .map_err(|e| internal(i, e))?,
                    );
                }
            }
            let want = s.view.get(&i).cloned().unwrap_or_default();
            if view != want {
                return Err(fail("view", i, show(&want), show(&view)));
            }

            // A validator whose core proposed ahead of the specification
            // differs from it in the proposal itself and in what follows
            // from it (the first proposal, the round, what the proposal
            // lets it decide); it is compared in full from the step that
            // creates the vertex. Its released sequence is still tracked.
            if waiting.contains(&i) {
                let ordered: Vec<VId> = core
                    .released
                    .iter()
                    .map(|r| self.named(r))
                    .collect::<Result<_, _>>()
                    .map_err(|e| internal(i, e))?;
                let ex = self.executed.get_mut(&i).expect("executed");
                if ordered.len() > ex.len() {
                    *ex = ordered;
                }
                continue;
            }

            let mut fp = BTreeMap::new();
            for (&r, by) in &core.first_proposals {
                for (&a, refs) in by {
                    let refs: BTreeSet<VId> = refs
                        .iter()
                        .map(|x| self.named(x))
                        .collect::<Result<_, _>>()
                        .map_err(|e| internal(i, e))?;
                    fp.insert((r, a), refs);
                }
            }
            let want = s.fp.get(&i).cloned().unwrap_or_default();
            if fp != want {
                let diff: Vec<_> = want
                    .iter()
                    .filter(|(k, v)| fp.get(k) != Some(v))
                    .map(|(k, v)| (k, v, fp.get(k)))
                    .collect();
                let extra: Vec<_> = fp.keys().filter(|k| !want.contains_key(k)).collect();
                return Err(fail(
                    "fp",
                    i,
                    format!("differing keys (key, spec, core): {diff:?}"),
                    format!("keys only the core holds: {extra:?}"),
                ));
            }

            let log: Vec<Entry> = core
                .decided_slots
                .iter()
                .map(|(sl, a)| Ok((*sl, a.as_ref().map(|a| self.named(a)).transpose()?)))
                .collect::<Result<_, String>>()
                .map_err(|e| internal(i, e))?;
            let want = s.log.get(&i).cloned().unwrap_or_default();
            if log != want {
                // What the core counted for each slot it decided otherwise.
                let mut why = String::new();
                for (k, e) in log.iter().enumerate() {
                    if want.get(k) == Some(e) {
                        continue;
                    }
                    let ((r, slot), _) = *e;
                    let leader = core.schedule.leader(r, slot);
                    let next: Vec<(ValidatorIndex, bool)> = core
                        .dag
                        .round(r + 1)
                        .map(|(a, _, v)| (a, v.references_author(leader)))
                        .collect();
                    let fp: Vec<(ValidatorIndex, bool)> = core
                        .first_proposals
                        .get(&(r + 1))
                        .map(|m| {
                            let mut x: Vec<_> = m
                                .iter()
                                .map(|(a, refs)| {
                                    (*a, refs.iter().any(|x| x.round == r && x.source == leader))
                                })
                                .collect();
                            x.sort();
                            x
                        })
                        .unwrap_or_default();
                    let _ = write!(
                        why,
                        " slot ({r}, {slot}) leader {leader}: next round (author, references leader) {next:?}, first proposals {fp:?};"
                    );
                }
                return Err(fail("log", i, show(&want), format!("{log:?} |{why}")));
            }

            let ordered: Vec<VId> = core
                .released
                .iter()
                .map(|r| self.named(r))
                .collect::<Result<_, _>>()
                .map_err(|e| internal(i, e))?;
            let want = s.ordered.get(&i).cloned().unwrap_or_default();
            if ordered != want {
                return Err(fail("ordered", i, show(&want), show(&ordered)));
            }

            let want = s.next_slot.get(&i).copied().unwrap_or((0, 0));
            if core.next_slot != want {
                return Err(fail("nextSlot", i, show(&want), show(&core.next_slot)));
            }

            let proposed = core.round.map_or(-1, |r| r as i64);
            let want = s.proposed.get(&i).copied().unwrap_or(-1);
            if proposed != want {
                return Err(fail("proposed", i, show(&want), show(&proposed)));
            }

            let ex = self.executed.get_mut(&i).expect("executed");
            if ordered.len() > ex.len() {
                *ex = ordered;
            }
            let want = s.executed.get(&i).cloned().unwrap_or_default();
            if *ex != want {
                return Err(fail("executed", i, show(&want), show(ex)));
            }
        }
        Ok(())
    }

    fn check_leaders(&self, s: &State) -> Result<(), Divergence> {
        let core = &self.cores[&self.honest[0]];
        for (&r, ls) in &s.leaders {
            let mine: Vec<ValidatorIndex> =
                (0..ls.len()).map(|k| core.schedule.leader(r, k)).collect();
            if mine != *ls {
                return Err(Divergence {
                    step: 0,
                    action: "Init".into(),
                    validator: None,
                    variable: "leaders",
                    spec: format!("round {r}: {ls:?}"),
                    core: format!("round {r}: {mine:?}"),
                });
            }
        }
        Ok(())
    }
}

fn replay(path: &Path) -> (Tally, Option<Divergence>) {
    let (n, f) = instance(path);
    let states = load(path);
    let mut r = Replay::new(n, f);
    assert_eq!(
        r.committee.quorum() as usize,
        n - (n - 1) / 3,
        "the committee's quorum is the specification's"
    );
    let result = (|| {
        let first = states.first().ok_or_else(|| Divergence {
            step: 0,
            action: "Init".into(),
            validator: None,
            variable: "replay",
            spec: String::new(),
            core: "empty trace".into(),
        })?;
        r.check_leaders(first)?;
        r.compare(first)?;
        for (k, s) in states.iter().enumerate().skip(1) {
            let at = |mut d: Divergence| {
                d.step = k;
                d
            };
            r.apply(&s.step, s).map_err(at)?;
            r.compare(s).map_err(at)?;
            r.tally.steps += 1;
            *r.tally.actions.entry(s.step.name()).or_default() += 1;
        }
        if let Some(id) = r.early.iter().next() {
            return Err(Divergence {
                step: states.len(),
                action: "end".into(),
                validator: Some(id.author),
                variable: "created",
                spec: format!("{id:?} never created"),
                core: "the core proposed it by itself".into(),
            });
        }
        Ok(())
    })();
    r.tally.traces = 1;
    if let Some(last) = states.last() {
        for log in last.log.values() {
            for (_, d) in log {
                if d.is_some() {
                    r.tally.commits += 1;
                } else {
                    r.tally.skips += 1;
                }
            }
        }
    }
    (r.tally, result.err())
}

fn traces(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("trace folder")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            let n = p.to_string_lossy();
            n.ends_with(".itf.json") || n.ends_with(".itf.json.gz")
        })
        .collect();
    out.sort();
    out
}

/// The instance an execution comes from, from its file name
/// `n<N>f<F>_<instance>_<seed>_<k>.itf.json.gz`: `c4quorum`, or
/// `c4quorum-noRejoin` for a run that ends where that witness is reached.
pub(super) fn instance_key(path: &Path) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.split('_').nth(1).unwrap_or("").to_string()
}

/// The order executions replay in, as indices into `keys` (each execution's
/// [`instance_key`]). Each round takes one execution of every instance (the
/// key up to its first `-`) that has any left, whichever family it belongs
/// to, and within an instance its own runs and its witness runs alternate. So
/// a replay stopped at any point has replayed as many executions of every
/// instance as of any other, give or take one, or all that instance had: no
/// instance goes past a count before every other has reached it.
pub(super) fn turns(keys: &[String]) -> Vec<usize> {
    use std::collections::VecDeque;
    let mut by: BTreeMap<&str, BTreeMap<&str, VecDeque<usize>>> = BTreeMap::new();
    for (i, k) in keys.iter().enumerate() {
        let base = k.split('-').next().unwrap_or(k);
        by.entry(base)
            .or_default()
            .entry(k.as_str())
            .or_default()
            .push_back(i);
    }
    let mut instances: Vec<VecDeque<usize>> = by
        .into_values()
        .map(|mut runs| {
            let mut q = VecDeque::new();
            while runs.values().any(|r| !r.is_empty()) {
                for r in runs.values_mut() {
                    q.extend(r.pop_front());
                }
            }
            q
        })
        .collect();
    let mut out = Vec::with_capacity(keys.len());
    while instances.iter().any(|q| !q.is_empty()) {
        for q in &mut instances {
            out.extend(q.pop_front());
        }
    }
    out
}

/// Replays `files` with `one` on `CONFORMANCE_THREADS` threads (default 1),
/// started in order. With `CONFORMANCE_DEADLINE` (Unix seconds) set, no
/// replay starts after it. Each file's result, in order; `None` for one not
/// replayed.
fn replay_all<I: Sync, T: Send>(files: &[I], one: impl Fn(&I) -> T + Sync) -> Vec<Option<T>> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let threads = std::env::var("CONFORMANCE_THREADS")
        .ok()
        .and_then(|t| t.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, files.len().max(1));
    let deadline = std::env::var("CONFORMANCE_DEADLINE")
        .ok()
        .and_then(|d| d.parse::<u64>().ok());
    let past = || {
        deadline.is_some_and(|d| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() >= d)
                .unwrap_or(false)
        })
    };
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<T>>> = files.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                while !past() {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(f) = files.get(i) else { break };
                    let r = one(f);
                    *results[i].lock().expect("result") = Some(r);
                }
            });
        }
    });
    results
        .into_iter()
        .map(|m| m.into_inner().expect("result"))
        .collect()
}

/// One line per instance: `INSTANCE <instance> replayed=<n> diverged=<n>
/// not-replayed=<n>`, from each file's outcome (`Some(diverged)`, or `None`
/// when it was not replayed).
pub(super) fn instance_lines(files: &[&Path], outcome: &[Option<bool>]) -> String {
    let mut by: BTreeMap<String, [usize; 3]> = BTreeMap::new();
    for (f, o) in files.iter().zip(outcome) {
        let c = by.entry(instance_key(f)).or_default();
        match o {
            Some(d) => {
                c[0] += 1;
                c[1] += usize::from(*d);
            }
            None => c[2] += 1,
        }
    }
    by.iter()
        .map(|(k, c)| {
            format!(
                "INSTANCE {k} replayed={} diverged={} not-replayed={}\n",
                c[0], c[1], c[2]
            )
        })
        .collect()
}

/// The commit rule's report: the summary, the count per instance and every
/// divergence, to stderr and `CONFORMANCE_REPORT`. The executions that
/// diverged.
fn commit_report(files: &[&Path], results: &[Option<(Tally, Option<Divergence>)>]) -> usize {
    let mut total = Tally::default();
    let mut report = String::new();
    let mut diverged = 0usize;
    for (p, r) in files.iter().zip(results) {
        let Some((t, d)) = r else { continue };
        total.add(t);
        if let Some(d) = d {
            diverged += 1;
            let _ = writeln!(
                report,
                "DIVERGE {} step {} {} validator {:?} variable {}\n  spec: {}\n  core: {}",
                p.display(),
                d.step,
                d.action,
                d.validator,
                d.variable,
                d.spec,
                d.core
            );
        }
    }
    let outcome: Vec<Option<bool>> = results
        .iter()
        .map(|r| r.as_ref().map(|(_, d)| d.is_some()))
        .collect();
    let summary = format!(
        "SUMMARY traces={} diverged={} not-replayed={} steps={} actions={:?} final-commits={} final-skips={}",
        total.traces,
        diverged,
        outcome.iter().filter(|o| o.is_none()).count(),
        total.steps,
        total.actions,
        total.commits,
        total.skips,
    );
    let instances = instance_lines(files, &outcome);
    eprintln!("{summary}");
    eprint!("{instances}{report}");
    if let Ok(out) = std::env::var("CONFORMANCE_REPORT") {
        std::fs::write(out, format!("{summary}\n{instances}{report}")).expect("report");
    }
    diverged
}

/// One replayed execution of either family.
enum Replayed {
    Commit((Tally, Option<Divergence>)),
    Vote(super::conformance_votes::Outcome),
}

/// Both families replayed in one pool: the commit rule's executions
/// (`COMMIT_RULE_TRACES`, report to `CONFORMANCE_REPORT`) and the checkpoint
/// votes' (`CHECKPOINT_VOTE_TRACES`, report to `CONFORMANCE_VOTE_REPORT`),
/// every instance of either taken in turn ([`turns`]), so one deadline cuts
/// all instances alike and neither family can take the other's time. A family
/// whose folder is not set is left out; one whose folder is empty is
/// reported as none replayed and fails the test after the other is replayed.
#[test]
fn conformance_replay() {
    use super::conformance_votes as votes;
    let commit_dir = std::env::var("COMMIT_RULE_TRACES").ok();
    let vote_dir = std::env::var("CHECKPOINT_VOTE_TRACES").ok();
    if commit_dir.is_none() && vote_dir.is_none() {
        eprintln!(
            "COMMIT_RULE_TRACES and CHECKPOINT_VOTE_TRACES are not set: no executions to replay"
        );
        return;
    }
    let commit_files = commit_dir
        .as_deref()
        .map(|d| traces(Path::new(d)))
        .unwrap_or_default();
    let vote_files = vote_dir
        .as_deref()
        .map(|d| votes::traces(Path::new(d)))
        .unwrap_or_default();
    // An empty folder is counted as none replayed before the test fails, so the stage reports it.
    let mut empty = Vec::new();
    if let Some(d) = commit_dir.as_deref().filter(|_| commit_files.is_empty()) {
        if let Ok(out) = std::env::var("CONFORMANCE_REPORT") {
            std::fs::write(out, "SUMMARY traces=0 diverged=0 not-replayed=0\n").expect("report");
        }
        empty.push(d.to_string());
    }
    if let Some(d) = vote_dir.as_deref().filter(|_| vote_files.is_empty()) {
        if let Ok(out) = std::env::var("CONFORMANCE_VOTE_REPORT") {
            std::fs::write(out, "SUMMARY votes traces=0 diverged=0 not-replayed=0\n")
                .expect("report");
        }
        empty.push(d.to_string());
    }
    let keys: Vec<String> = commit_files
        .iter()
        .chain(&vote_files)
        .map(|p| instance_key(p))
        .collect();
    let items: Vec<(bool, &Path)> = turns(&keys)
        .into_iter()
        .map(|i| match commit_files.get(i) {
            Some(p) => (false, p.as_path()),
            None => (true, vote_files[i - commit_files.len()].as_path()),
        })
        .collect();
    let results = replay_all(&items, |&(vote, p)| {
        if vote {
            Replayed::Vote(votes::replay(p))
        } else {
            Replayed::Commit(replay(p))
        }
    });
    let (mut cf, mut cr, mut vf, mut vr) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (&(vote, p), r) in items.iter().zip(results) {
        if vote {
            vf.push(p);
            vr.push(match r {
                Some(Replayed::Vote(o)) => Some(o),
                _ => None,
            });
        } else {
            cf.push(p);
            cr.push(match r {
                Some(Replayed::Commit(o)) => Some(o),
                _ => None,
            });
        }
    }
    let mut diverged = 0;
    if !commit_files.is_empty() {
        diverged += commit_report(&cf, &cr);
    }
    if !vote_files.is_empty() {
        diverged += votes::vote_report(&vf, &vr);
    }
    assert!(empty.is_empty(), "no traces in {}", empty.join(", "));
    assert_eq!(
        diverged, 0,
        "{diverged} executions diverged from the specification"
    );
}

#[test]
fn every_instance_reaches_a_count_before_any_goes_past_it() {
    // c4 has its own runs and runs of two witnesses, v4 and c7 only their
    // own: taking each key in turn would give c4 three replays for v4's one.
    let mut keys: Vec<String> = Vec::new();
    for _ in 0..6 {
        keys.extend(["c4", "c4-noSkip", "c4-noRejoin-stepFirst"].map(String::from));
    }
    keys.extend(["v4"; 4].map(String::from));
    keys.extend(["c7"; 2].map(String::from));
    keys.extend(["v4any-noRefusal"; 3].map(String::from));
    let order = turns(&keys);
    let mut seen = order.clone();
    seen.sort();
    assert_eq!(seen, (0..keys.len()).collect::<Vec<_>>());
    let base = |k: &String| k.split('-').next().unwrap_or(k).to_string();
    let mut total: BTreeMap<String, usize> = BTreeMap::new();
    for k in &keys {
        *total.entry(base(k)).or_default() += 1;
    }
    let mut done: BTreeMap<String, usize> = BTreeMap::new();
    for &i in &order {
        *done.entry(base(&keys[i])).or_default() += 1;
        let most = done.values().copied().max().unwrap_or(0);
        for (inst, n) in &total {
            let d = done.get(inst).copied().unwrap_or(0);
            assert!(
                d == *n || d + 1 >= most,
                "{inst} at {d} of {n} while another is at {most}"
            );
        }
    }
    // Within c4 its own runs and its witnesses' alternate.
    let c4: Vec<&str> = order
        .iter()
        .map(|&i| keys[i].as_str())
        .filter(|k| k.starts_with("c4"))
        .take(3)
        .collect();
    assert_eq!(c4, ["c4", "c4-noRejoin-stepFirst", "c4-noSkip"]);
}

/// Prints the core's leader table for the replay committees, from which the
/// specification's conformance instances take theirs.
#[test]
fn commit_replay_leader_tables() {
    if std::env::var("CONFORMANCE_PRINT_LEADERS").is_err() {
        return;
    }
    for n in [4usize, 7] {
        let r = Replay::new(n, (n - 1) / 3);
        let core = &r.cores[&0];
        let rounds: Vec<String> = (0..=12)
            .map(|round| {
                let ls: Vec<String> = (0..core.schedule.slots())
                    .map(|k| core.schedule.leader(round, k).to_string())
                    .collect();
                format!("{round} -> [{}]", ls.join(", "))
            })
            .collect();
        println!(
            "n={n} quorum={} lookahead={} slots={} LEADERS = Map({})",
            core.committee.quorum(),
            core.schedule.lookahead(),
            core.schedule.slots(),
            rounds.join(", ")
        );
    }
}
