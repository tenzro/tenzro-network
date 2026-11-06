//! Replays executions of the checkpoint vote specification
//! (`spec/checkpoint_votes.qnt`) through the code, step by step: each honest
//! validator's signing goes through [`sign_checkpoint`] with its own
//! high-water mark, and each honest collector is a real [`Core`] receiving
//! the votes ([`Core::on_messages`], or [`Core::on_own_vote`] for its own).
//!
//! Compared after every step: whether a signing request was refused, and
//! per honest collector the certificates it keeps (index and body) and the
//! equivocation evidence it reported (signer and index).
//!
//! A file's name starts with `n<N>f<F>_`. `CHECKPOINT_VOTE_TRACES` names the
//! folder of traces; without it the replay does nothing.
//! `CONFORMANCE_VOTE_REPORT` names a file the summary, the count per instance
//! and every divergence are written to. The executions replay in one pool
//! with the commit rule's (`conformance_replay` in its module), every
//! instance of both taken in turn, with its threads and deadline
//! (`CONFORMANCE_THREADS`, `CONFORMANCE_DEADLINE`).

use super::*;
use crate::checkpoint::test_support::MemoryHighWater;
use crate::checkpoint::{Checkpoint, CheckpointVote, sign_checkpoint};
use crate::config::{ConsensusConfig, TimeRules};
use crate::harness::tdc::{committee, genesis_start};
use crate::session::SessionCertificate;
use crate::validator_key::ValidatorSigner;
use crate::validator_key::test_signer::SoftwareTestSigner;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

const GENESIS: Digest = [0x11; 32];
const NOW: u64 = 0;

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

fn ints(v: &Value) -> Vec<i64> {
    items(v, "#tup").iter().map(int).collect()
}

#[derive(Debug, Clone)]
enum Step {
    Init,
    Sign(ValidatorIndex, u64, u8),
    Receive(ValidatorIndex, ValidatorIndex, u64, u8),
}

struct State {
    step: Step,
    outcome: String,
    certs: BTreeMap<ValidatorIndex, BTreeMap<u64, u8>>,
    evidence: BTreeMap<ValidatorIndex, BTreeSet<(ValidatorIndex, u64)>>,
}

fn state(raw: &Value) -> State {
    let obj = raw.as_object().expect("state");
    let var = |name: &str| -> &Value {
        obj.iter()
            .find(|(k, _)| *k == name || k.ends_with(&format!("::{name}")))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("no variable {name}"))
    };
    let pairs = |v: &Value| -> Vec<(Value, Value)> {
        items(v, "#map")
            .iter()
            .map(|kv| {
                let kv = kv.as_array().expect("entry");
                (kv[0].clone(), kv[1].clone())
            })
            .collect()
    };
    let step = {
        let s = var("lastStep");
        match s["tag"].as_str().expect("tag") {
            "Init" => Step::Init,
            "Sign" => {
                let t = ints(&s["value"]);
                Step::Sign(t[0] as ValidatorIndex, t[1] as u64, t[2] as u8)
            }
            "Receive" => {
                let t = ints(&s["value"]);
                Step::Receive(
                    t[0] as ValidatorIndex,
                    t[1] as ValidatorIndex,
                    t[2] as u64,
                    t[3] as u8,
                )
            }
            other => panic!("unknown step {other}"),
        }
    };
    let outcome = {
        let o = var("outcome");
        let t = o["tag"].as_str().expect("tag");
        match t {
            "Certified" | "Evidence" => format!("{t}({})", int(&o["value"])),
            _ => t.to_string(),
        }
    };
    State {
        step,
        outcome,
        certs: pairs(var("certs"))
            .into_iter()
            .map(|(i, m)| {
                (
                    int(&i) as ValidatorIndex,
                    pairs(&m)
                        .into_iter()
                        .map(|(k, b)| (int(&k) as u64, int(&b) as u8))
                        .collect(),
                )
            })
            .collect(),
        evidence: pairs(var("evidence"))
            .into_iter()
            .map(|(i, s)| {
                (
                    int(&i) as ValidatorIndex,
                    items(&s, "#set")
                        .iter()
                        .map(|e| {
                            let t = ints(e);
                            (t[0] as ValidatorIndex, t[1] as u64)
                        })
                        .collect(),
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
    v["states"]
        .as_array()
        .expect("states")
        .iter()
        .map(state)
        .collect()
}

fn instance(path: &Path) -> (usize, usize) {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let head = name.split('_').next().unwrap_or("");
    let (n, f) = head
        .strip_prefix('n')
        .and_then(|r| r.split_once('f'))
        .unwrap_or_else(|| panic!("trace name {name} does not start with n<N>f<F>_"));
    (n.parse().expect("N"), f.parse().expect("F"))
}

/// Body `b` of index `k`: it follows body `b / 2` of index `k - 1`.
fn checkpoint(k: u64, b: u8) -> Checkpoint {
    let mut bodies = vec![b];
    for _ in 0..k {
        let last = *bodies.last().expect("non-empty");
        bodies.push(last / 2);
    }
    bodies.reverse();
    let mut prev = [0u8; 32];
    let mut cp = None;
    for (j, body) in bodies.into_iter().enumerate() {
        let c = Checkpoint {
            chain_id: 7,
            genesis_hash: GENESIS,
            epoch: 0,
            index: j as u64,
            prev,
            first_height: 1,
            last_height: 1,
            blocks_root: [2; 32],
            state_height: 0,
            state_root: [body; 32],
            statement_root: [0; 32],
            next_committee_root: None,
            ordering_root: [0; 32],
            anchor_round: 0,
            timestamp_ms: 0,
        };
        prev = c.digest();
        cp = Some(c);
    }
    cp.expect("index 0 at least")
}

struct Signer {
    session: SoftwareTestSigner,
    certificate: SessionCertificate,
    high_water: MemoryHighWater,
}

pub(super) struct Divergence {
    step: usize,
    action: String,
    detail: String,
}

struct Replay {
    honest: Vec<ValidatorIndex>,
    signers: Vec<Signer>,
    cores: BTreeMap<ValidatorIndex, Core>,
    votes: BTreeMap<(ValidatorIndex, u64, u8), CheckpointVote>,
    evidence: BTreeMap<ValidatorIndex, BTreeSet<(ValidatorIndex, u64)>>,
    checkpoints: BTreeMap<(u64, u8), Checkpoint>,
}

impl Replay {
    fn new(n: usize, f: usize) -> Self {
        let (committee, hardware) = committee(n, n as u64);
        let cfg = ConsensusConfig::default().core(7, GENESIS, &TimeRules::default());
        let honest: Vec<ValidatorIndex> = (0..(n - f) as ValidatorIndex).collect();
        let signers = hardware
            .iter()
            .enumerate()
            .map(|(i, hw)| {
                let session = SoftwareTestSigner::from_seed(1_000_000 + i as u64);
                let certificate = crate::session::sign_certificate(
                    &**hw as &dyn ValidatorSigner,
                    7,
                    GENESIS,
                    0,
                    session.public_key().clone(),
                )
                .expect("session certificate");
                Signer {
                    session,
                    certificate,
                    high_water: MemoryHighWater::default(),
                }
            })
            .collect();
        let cores = honest
            .iter()
            .map(|&i| {
                (
                    i,
                    Core::new(cfg.clone(), committee.clone(), i, genesis_start()),
                )
            })
            .collect();
        Self {
            honest: honest.clone(),
            signers,
            cores,
            votes: BTreeMap::new(),
            evidence: honest.iter().map(|&i| (i, BTreeSet::new())).collect(),
            checkpoints: BTreeMap::new(),
        }
    }

    fn cp(&mut self, k: u64, b: u8) -> Checkpoint {
        self.checkpoints
            .entry((k, b))
            .or_insert_with(|| checkpoint(k, b))
            .clone()
    }

    /// Applies a step; returns the outcome the code produced.
    fn apply(&mut self, step: &Step) -> String {
        match *step {
            Step::Init => "None".into(),
            Step::Sign(s, k, b) => {
                let cp = self.cp(k, b);
                let signer = &self.signers[s as usize];
                let byzantine = !self.honest.contains(&s);
                let fresh = MemoryHighWater::default();
                let hw: &MemoryHighWater = if byzantine {
                    &fresh
                } else {
                    &signer.high_water
                };
                match sign_checkpoint(&signer.session, &signer.certificate, hw, s, &cp) {
                    Ok(v) => {
                        self.votes.entry((s, k, b)).or_insert(v);
                        "Signed".into()
                    }
                    Err(_) => "Refused".into(),
                }
            }
            Step::Receive(i, s, k, b) => {
                let vote = self.votes[&(s, k, b)].clone();
                let core = self.cores.get_mut(&i).expect("honest collector");
                if i == s {
                    core.on_own_vote(vote);
                } else {
                    core.on_messages(s, vec![Message::Vote(vote)], NOW);
                }
                core.take_outbox();
                let mut out = String::new();
                let mut certified = false;
                for e in core.take_events() {
                    // A certificate the collector forms is reported even when
                    // it is at once dropped as the oldest of those kept.
                    if let Event::Certified(c) = &e {
                        certified |= c.checkpoint.index == k;
                    }
                    if let Event::Equivocation(eq) = e {
                        let who = core
                            .committee
                            .members()
                            .iter()
                            .position(|m| m.public_key == eq.public_key)
                            .expect("a member") as ValidatorIndex;
                        self.evidence
                            .get_mut(&i)
                            .expect("collector")
                            .insert((who, eq.first.index));
                        out = format!("Evidence({who})");
                    }
                }
                if certified {
                    out = format!("Certified({k})");
                }
                if out.is_empty() {
                    "Held or Ignored".into()
                } else {
                    out
                }
            }
        }
    }

    fn compare(&self, s: &State, outcome: &str) -> Result<(), String> {
        let spec_outcome = match s.outcome.as_str() {
            "Held" | "Ignored" => "Held or Ignored",
            o => o,
        };
        if spec_outcome != outcome && !(matches!(s.step, Step::Init)) {
            return Err(format!("outcome: spec {} code {outcome}", s.outcome));
        }
        for &i in &self.honest {
            let core = &self.cores[&i];
            let certs: BTreeMap<u64, u8> = core
                .certificates
                .iter()
                .map(|(k, c)| (*k, c.checkpoint.state_root[0]))
                .collect();
            let want = s.certs.get(&i).cloned().unwrap_or_default();
            if certs != want {
                return Err(format!("certs of {i}: spec {want:?} code {certs:?}"));
            }
            let want = s.evidence.get(&i).cloned().unwrap_or_default();
            if self.evidence[&i] != want {
                return Err(format!(
                    "evidence of {i}: spec {want:?} code {:?}",
                    self.evidence[&i]
                ));
            }
        }
        Ok(())
    }
}

/// A replayed execution: its steps, the count of each action and outcome,
/// and where it diverged.
pub(super) type Outcome = (usize, BTreeMap<&'static str, usize>, Option<Divergence>);

pub(super) fn replay(path: &Path) -> Outcome {
    let (n, f) = instance(path);
    let states = load(path);
    let mut r = Replay::new(n, f);
    let mut actions: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (k, s) in states.iter().enumerate() {
        let outcome = r.apply(&s.step);
        let name = match s.step {
            Step::Init => "init",
            Step::Sign(..) => "sign",
            Step::Receive(..) => "receive",
        };
        *actions.entry(name).or_default() += 1;
        *actions
            .entry(match s.outcome.split('(').next().unwrap_or("") {
                "Refused" => "outcome-refused",
                "Signed" => "outcome-signed",
                "Ignored" => "outcome-ignored",
                "Held" => "outcome-held",
                "Certified" => "outcome-certified",
                "Evidence" => "outcome-evidence",
                _ => "outcome-none",
            })
            .or_default() += 1;
        if let Err(detail) = r.compare(s, &outcome) {
            return (
                k,
                actions,
                Some(Divergence {
                    step: k,
                    action: format!("{:?}", s.step),
                    detail,
                }),
            );
        }
    }
    (states.len(), actions, None)
}

pub(super) fn traces(dir: &Path) -> Vec<PathBuf> {
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

/// The checkpoint votes' report: the summary, the count per instance and
/// every divergence, to stderr and `CONFORMANCE_VOTE_REPORT`. The executions
/// that diverged. The replay itself is the commit rule's
/// `conformance_replay`, which takes both families' instances in turn.
pub(super) fn vote_report(files: &[&Path], results: &[Option<Outcome>]) -> usize {
    let (mut steps, mut diverged, mut replayed) = (0usize, 0usize, 0usize);
    let mut actions: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut report = String::new();
    for (p, r) in files.iter().zip(results) {
        let Some((k, a, d)) = r else { continue };
        replayed += 1;
        steps += k;
        for (x, c) in a {
            *actions.entry(x).or_default() += c;
        }
        if let Some(d) = d {
            diverged += 1;
            let _ = writeln!(
                report,
                "DIVERGE {} step {} {}\n  {}",
                p.display(),
                d.step,
                d.action,
                d.detail
            );
        }
    }
    let outcome: Vec<Option<bool>> = results
        .iter()
        .map(|r| r.as_ref().map(|(_, _, d)| d.is_some()))
        .collect();
    let summary = format!(
        "SUMMARY votes traces={replayed} diverged={diverged} not-replayed={} steps={steps} actions={actions:?}",
        files.len() - replayed
    );
    let instances = super::conformance::instance_lines(files, &outcome);
    eprintln!("{summary}");
    eprint!("{instances}{report}");
    if let Ok(out) = std::env::var("CONFORMANCE_VOTE_REPORT") {
        std::fs::write(out, format!("{summary}\n{instances}{report}")).expect("report");
    }
    diverged
}
