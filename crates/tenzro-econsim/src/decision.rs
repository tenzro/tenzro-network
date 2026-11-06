//! Decisions the simulated populations take, and the policies that take them.
//!
//! Four economic roles decide at decision points (every simulated week, and
//! the next day boundary after the price moves by a quarter or more since
//! the role's last decision): machine buyers choose how much compute to
//! rent, providers choose their price against the market rate, validators
//! choose whether to attest providers' availability, and arbitrageurs
//! choose whether to trade the pool. Each role has a closed menu; the
//! chosen action stands until the role's next decision.
//!
//! [`Rules`] is the default policy: every role takes the action that is the
//! simulation's own behaviour, so a run under it is the run the populations
//! make without any policy. [`ModelPolicy`] asks a model served on the
//! network, through a content-addressed answer cache:
//!
//! - the request is built from the state rounded to fixed buckets, in a
//!   canonical form, under a versioned prompt template;
//! - the answer must name one action of the role's menu; anything else is an
//!   invalid answer, which keeps the standing action and is counted;
//! - the cache key covers the model hash, the template version, the
//!   canonical state, the decoding settings and a seed derived from the run
//!   seed, the agent and the hour;
//! - [`Mode::Record`] calls the network on a miss and stores the answer,
//!   [`Mode::Replay`] reads the cache only and fails the run on a miss,
//!   [`Mode::LiveProbe`] replays and also re-asks a fixed sample of keys
//!   live, reporting how often the live answer agrees.
//!
//! A run is reproducible from the binary, its configuration, its seed and
//! the cache's manifest hash ([`Cache::manifest_hash`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hours between scheduled decisions.
pub const DECISION_EVERY_H: u64 = 7 * 24;

/// A price move since a role's last decision that brings its next decision
/// forward to the next day boundary, as |log2(price / price then)|.
pub const EVENT_LOG2_MOVE: f64 = 0.32;

/// Share of the pool's USD depth one arbitrageur population trades in a
/// day when it buys or sells, split over its agents.
pub const ARB_DAILY_DEPTH_SHARE: f64 = 0.01;

/// An economic role that decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Machine buyers renting compute.
    Buyer,
    /// Compute providers pricing their hours.
    Provider,
    /// Validators attesting providers' availability.
    Validator,
    /// Traders between the pool and the outside market.
    Arbitrageur,
}

impl Role {
    /// Every role, in decision order.
    pub const ALL: [Role; 4] = [
        Role::Buyer,
        Role::Provider,
        Role::Validator,
        Role::Arbitrageur,
    ];

    /// Short name.
    pub fn name(self) -> &'static str {
        match self {
            Role::Buyer => "buyer",
            Role::Provider => "provider",
            Role::Validator => "validator",
            Role::Arbitrageur => "arbitrageur",
        }
    }

    /// The closed menu of actions, each with what it does.
    pub fn menu(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Role::Buyer => &[
                ("reduce", "rent half the compute your workload calls for"),
                ("keep", "rent the compute your workload calls for"),
                (
                    "expand",
                    "rent one and a half times the compute your workload calls for",
                ),
            ],
            Role::Provider => &[
                ("undercut", "list your hours 10% below the market rate"),
                ("list", "list your hours at the market rate"),
                ("premium", "list your hours 10% above the market rate"),
            ],
            Role::Validator => &[
                (
                    "attest",
                    "attest every provider's availability each epoch, paying the fees",
                ),
                (
                    "abstain",
                    "skip the attestations this week and save their fees",
                ),
            ],
            Role::Arbitrageur => &[
                ("sell", "sell TNZO into the pool each day"),
                ("none", "do not trade"),
                ("buy", "buy TNZO from the pool each day"),
            ],
        }
    }

    /// Index in the menu of the simulation's own behaviour.
    pub fn default_action(self) -> usize {
        match self {
            Role::Buyer => 1,
            Role::Provider => 1,
            Role::Validator => 0,
            Role::Arbitrageur => 1,
        }
    }

    /// What the role does, for the prompt.
    fn brief(self) -> &'static str {
        match self {
            Role::Buyer => {
                "You buy compute for a fleet of software agents. They rent model-serving hours \
                 from providers on the network and pay for them in TNZO, which they buy at the \
                 pool price."
            }
            Role::Provider => {
                "You operate machines that serve rented compute hours on the network. You are \
                 paid in TNZO per hour served and sell what you earn at the pool price."
            }
            Role::Validator => {
                "You run a validator. Each market epoch you may attest whether each provider was \
                 available; attestations cost transaction fees, and the network's service checks \
                 and insurance payouts rely on them."
            }
            Role::Arbitrageur => {
                "You trade TNZO against USD on the network's pool. The chain prices fees at a \
                 rate its validators report, which can differ from the pool price."
            }
        }
    }

    /// Menu index of `word`, if it names an action.
    pub fn parse(self, word: &str) -> Option<usize> {
        self.menu().iter().position(|(w, _)| *w == word)
    }
}

/// One role's action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    /// Role deciding.
    pub role: Role,
    /// Index into the role's menu.
    pub index: usize,
}

impl Action {
    /// The action's name.
    pub fn name(self) -> &'static str {
        self.role.menu()[self.index].0
    }
}

/// What a role sees when it decides: the state rounded to fixed buckets.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Role deciding.
    pub role: Role,
    /// Agent within the role.
    pub agent: u32,
    /// Simulated hour since genesis.
    pub hour: u64,
    /// The action standing now, as a menu index.
    pub current: usize,
    /// Rounded state, integers only.
    pub state: BTreeMap<&'static str, i64>,
}

/// What each field of [`Observation::state`] means, for the prompt.
pub const STATE_LEGEND: &[(&str, &str)] = &[
    ("week", "weeks since genesis"),
    ("price_q", "TNZO pool price in USD as round(4*log2(price))"),
    (
        "price_move_q",
        "price move since your last decision as round(4*log2(now/then))",
    ),
    (
        "demand_pct",
        "compute demand against the starting demand, percent, 10-point buckets",
    ),
    (
        "fee_q",
        "fee of a plain transfer in USD as round(4*log2(fee))",
    ),
    (
        "rate_gap_pct",
        "chain rate over pool price minus one, percent, 5-point buckets",
    ),
    (
        "providers_pct",
        "providers serving, percent of all providers, 10-point buckets",
    ),
    (
        "streams_pct",
        "rented compute streams open, percent of the base workload, 10-point buckets",
    ),
    (
        "margin_pct",
        "provider margin per compute hour, percent of the hour price, 10-point buckets",
    ),
    ("validators", "bonded validators"),
];

impl Observation {
    /// Canonical form: sorted keys, integers and fixed names only.
    pub fn canonical(&self) -> String {
        let mut m: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        m.insert("role", self.role.name().into());
        m.insert("current", self.role.menu()[self.current].0.into());
        for (k, v) in &self.state {
            m.insert(k, (*v).into());
        }
        serde_json::to_string(&m).expect("canonical state")
    }
}

/// Rounds `x` to the nearest multiple of `step`.
pub fn bucket(x: f64, step: f64) -> i64 {
    if !x.is_finite() {
        return 0;
    }
    ((x / step).round() * step) as i64
}

/// round(4*log2(x)), with non-positive values at the floor.
pub fn log_q(x: f64) -> i64 {
    if x.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) || !x.is_finite() {
        return -400;
    }
    (4.0 * x.log2()).round().clamp(-400.0, 400.0) as i64
}

/// Seed of one decision, from the run seed, the agent and the hour.
pub fn decision_seed(run_seed: u64, role: Role, agent: u32, hour: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(b"tenzro-econsim/decision-seed/1\0");
    h.update(run_seed.to_le_bytes());
    h.update(role.name().as_bytes());
    h.update([0]);
    h.update(agent.to_le_bytes());
    h.update(hour.to_le_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().expect("8 bytes"))
}

/// Takes the populations' decisions.
pub trait DecisionPolicy: Send + Sync {
    /// Name for reports.
    fn name(&self) -> String;
    /// The action for `obs` in the run seeded `run_seed`. An error fails the
    /// run.
    fn decide(&self, run_seed: u64, obs: &Observation) -> Result<Action, String>;
}

/// The simulation's own behaviour: every role takes its default action.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rules;

impl DecisionPolicy for Rules {
    fn name(&self) -> String {
        "rules".into()
    }

    fn decide(&self, _run_seed: u64, obs: &Observation) -> Result<Action, String> {
        Ok(Action {
            role: obs.role,
            index: obs.role.default_action(),
        })
    }
}

/// The policy a run uses; [`Rules`] unless set.
#[derive(Clone)]
pub struct Policy(pub Arc<dyn DecisionPolicy>);

impl Default for Policy {
    fn default() -> Self {
        Policy(Arc::new(Rules))
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Policy({})", self.0.name())
    }
}

impl Serialize for Policy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.name())
    }
}

/// Prompt template, versioned: a template's text never changes under its
/// version; a change is a new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Template {
    /// Key=value lines.
    Lines1,
    /// One JSON object.
    Json1,
    /// Sentences.
    Prose1,
}

impl Template {
    /// Every template.
    pub const ALL: [Template; 3] = [Template::Lines1, Template::Json1, Template::Prose1];

    /// Version string, part of the cache key.
    pub fn version(self) -> &'static str {
        match self {
            Template::Lines1 => "lines-1",
            Template::Json1 => "json-1",
            Template::Prose1 => "prose-1",
        }
    }

    /// Template named `s`.
    pub fn parse(s: &str) -> Option<Template> {
        Template::ALL.into_iter().find(|t| t.version() == s)
    }

    /// The request text for `obs`.
    pub fn render(self, obs: &Observation) -> String {
        let role = obs.role;
        let menu = role.menu();
        let names: Vec<&str> = menu.iter().map(|(w, _)| *w).collect();
        let legend = |k: &str| {
            STATE_LEGEND
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, d)| *d)
                .unwrap_or("")
        };
        match self {
            Template::Lines1 => {
                let mut s = format!("ROLE\n{}\n\nSTATE\n", role.brief());
                for (k, v) in &obs.state {
                    s.push_str(&format!("{k}={v}  # {}\n", legend(k)));
                }
                s.push_str(&format!(
                    "current_action={}\n\nACTIONS\n",
                    menu[obs.current].0
                ));
                for (w, d) in menu {
                    s.push_str(&format!("{w}: {d}\n"));
                }
                s.push_str(&format!(
                    "\nReply with exactly one word from: {}.\n",
                    names.join(", ")
                ));
                s
            }
            Template::Json1 => {
                let state: BTreeMap<&str, serde_json::Value> = obs
                    .state
                    .iter()
                    .map(|(k, v)| (*k, serde_json::json!({ "value": v, "meaning": legend(k) })))
                    .collect();
                let actions: BTreeMap<&str, &str> = menu.iter().copied().collect();
                let body = serde_json::json!({
                    "role": role.brief(),
                    "state": state,
                    "current_action": menu[obs.current].0,
                    "actions": actions,
                    "reply": format!("exactly one word from: {}", names.join(", ")),
                });
                serde_json::to_string_pretty(&body).expect("prompt json")
            }
            Template::Prose1 => {
                let mut s = format!("{} ", role.brief());
                s.push_str("Here is where things stand. ");
                for (k, v) in &obs.state {
                    s.push_str(&format!("The {} is {v}. ", legend(k)));
                }
                s.push_str(&format!(
                    "You are currently following the action \"{}\". Your choices are: ",
                    menu[obs.current].0
                ));
                let opts: Vec<String> =
                    menu.iter().map(|(w, d)| format!("\"{w}\" ({d})")).collect();
                s.push_str(&opts.join("; "));
                s.push_str(&format!(
                    ". Which do you choose for the coming week? Reply with exactly one word from: {}.",
                    names.join(", ")
                ));
                s
            }
        }
    }
}

/// Decoding settings, part of the cache key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decode {
    /// Sampling temperature.
    pub temperature: f64,
    /// Nucleus mass.
    pub top_p: f64,
    /// Output token cap.
    pub max_tokens: u32,
    /// Stop sequences.
    pub stop: Vec<String>,
}

impl Default for Decode {
    fn default() -> Self {
        Decode {
            temperature: 0.6,
            top_p: 0.9,
            max_tokens: 8,
            stop: vec!["\n".into()],
        }
    }
}

impl Decode {
    /// Canonical form with fixed decimals.
    pub fn canonical(&self) -> String {
        format!(
            "t={:.3};p={:.3};n={};stop={}",
            self.temperature,
            self.top_p,
            self.max_tokens,
            serde_json::to_string(&self.stop).expect("stop")
        )
    }
}

/// A registry model: its id and the SHA-256 the registry holds for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    /// Registry model id.
    pub id: String,
    /// Registry model hash, hex.
    pub hash: String,
}

/// Cache key of one request.
pub fn cache_key(
    model: &ModelRef,
    t: Template,
    canonical_state: &str,
    d: &Decode,
    seed: u64,
) -> String {
    let mut h = Sha256::new();
    for part in [
        model.hash.as_bytes(),
        t.version().as_bytes(),
        canonical_state.as_bytes(),
        d.canonical().as_bytes(),
    ] {
        h.update(part);
        h.update([0]);
    }
    h.update(seed.to_le_bytes());
    hex::encode(h.finalize())
}

/// One cached answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Action named, or `invalid` when the answer named none.
    pub action: String,
    /// The model's text.
    pub raw: String,
    /// Model id served.
    pub model_id: String,
    /// Model hash the key was built with.
    pub model_hash: String,
    /// Template version.
    pub template: String,
    /// Role and hour, for reading the cache.
    pub role: String,
    /// Simulated hour.
    pub hour: u64,
    /// The node's signed receipt, when the call returned one.
    #[serde(default)]
    pub receipt: Option<serde_json::Value>,
    /// Metered cost, wei.
    #[serde(default)]
    pub cost_wei: Option<String>,
    /// How the call settled.
    #[serde(default)]
    pub settlement: Option<serde_json::Value>,
    /// Tokens in.
    #[serde(default)]
    pub input_tokens: Option<u64>,
    /// Tokens out.
    #[serde(default)]
    pub output_tokens: Option<u64>,
}

/// The answer cache.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cache {
    /// Format version.
    pub version: u32,
    /// Answers by key.
    pub entries: BTreeMap<String, Entry>,
}

impl Cache {
    /// Loads `path`; a missing file is an empty cache.
    pub fn load(path: &Path) -> Result<Cache, String> {
        match std::fs::read(path) {
            Ok(b) => {
                serde_json::from_slice(&b).map_err(|e| format!("cache {}: {e}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Cache {
                version: 1,
                entries: BTreeMap::new(),
            }),
            Err(e) => Err(format!("cache {}: {e}", path.display())),
        }
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = serde_json::to_vec_pretty(self).expect("cache json");
        b.push(b'\n');
        b
    }

    /// Writes the cache to `path`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// SHA-256 of the canonical bytes, hex: the hash a run manifest records.
    pub fn manifest_hash(&self) -> String {
        hex::encode(Sha256::digest(self.to_bytes()))
    }
}

/// One request to a served model.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Registry model id.
    pub model_id: &'a str,
    /// Request text.
    pub prompt: &'a str,
    /// Decoding settings.
    pub decode: &'a Decode,
    /// Sampler seed.
    pub seed: u64,
}

/// A served model's reply.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    /// Output text.
    pub text: String,
    /// The node's signed receipt.
    pub receipt: Option<serde_json::Value>,
    /// Metered cost, wei.
    pub cost_wei: Option<String>,
    /// How the call settled.
    pub settlement: Option<serde_json::Value>,
    /// Tokens in.
    pub input_tokens: Option<u64>,
    /// Tokens out.
    pub output_tokens: Option<u64>,
}

/// Carries requests to models served on the network.
pub trait Transport: Send + Sync {
    /// Sends `req`; an error fails the run.
    fn complete(&self, req: &Request<'_>) -> Result<Reply, String>;
}

/// How [`ModelPolicy`] uses the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Call the network on a miss and store the answer.
    Record,
    /// Cache only; a miss fails the run.
    Replay,
    /// Cache only, and re-ask `per_mille` of the keys live.
    LiveProbe {
        /// Keys re-asked, per thousand, chosen by key.
        per_mille: u32,
    },
}

impl Mode {
    /// Name for reports.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Record => "record",
            Mode::Replay => "replay",
            Mode::LiveProbe { .. } => "live-probe",
        }
    }
}

/// Counters over every decision a [`ModelPolicy`] took.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Stats {
    /// Decisions taken.
    pub decisions: u64,
    /// Answered from the cache.
    pub hits: u64,
    /// Answered by the network and stored.
    pub recorded: u64,
    /// Answers that named no action; the standing action was kept.
    pub invalid: u64,
    /// Decisions by role and action.
    pub actions: BTreeMap<String, u64>,
    /// Network calls made (record and probe).
    pub calls: u64,
    /// Calls that returned a signed receipt.
    pub receipts: u64,
    /// Metered cost over the calls, wei.
    pub cost_wei: u128,
    /// Calls whose settlement the reply reported.
    pub settled: u64,
    /// Keys re-asked live.
    pub probed: u64,
    /// Live answers that agreed with the cache.
    pub agreed: u64,
    /// First disagreements: key, cached action, live action.
    pub disagreements: Vec<(String, String, String)>,
}

/// Decides by asking a served model, through the answer cache.
pub struct ModelPolicy {
    /// Model asked.
    pub model: ModelRef,
    /// Prompt template.
    pub template: Template,
    /// Decoding settings.
    pub decode: Decode,
    /// Network use.
    pub mode: Mode,
    cache: Mutex<Cache>,
    transport: Option<Arc<dyn Transport>>,
    stats: Mutex<Stats>,
}

impl ModelPolicy {
    /// A policy over `cache`; `transport` is required unless `mode` is
    /// [`Mode::Replay`].
    pub fn new(
        model: ModelRef,
        template: Template,
        decode: Decode,
        mode: Mode,
        cache: Cache,
        transport: Option<Arc<dyn Transport>>,
    ) -> Result<Self, String> {
        if mode != Mode::Replay && transport.is_none() {
            return Err(format!("{} needs a transport to the network", mode.name()));
        }
        if model.hash.len() != 64 || model.hash.bytes().all(|b| b == b'0') {
            return Err(format!("model {} has no registry hash", model.id));
        }
        Ok(ModelPolicy {
            model,
            template,
            decode,
            mode,
            cache: Mutex::new(cache),
            transport,
            stats: Mutex::new(Stats::default()),
        })
    }

    /// The cache as it stands.
    pub fn cache(&self) -> Cache {
        self.cache.lock().expect("cache").clone()
    }

    /// Counters so far.
    pub fn stats(&self) -> Stats {
        self.stats.lock().expect("stats").clone()
    }

    fn ask(&self, prompt: &str, seed: u64, obs: &Observation) -> Result<Entry, String> {
        let t = self.transport.as_ref().ok_or("no transport")?;
        let reply = t.complete(&Request {
            model_id: &self.model.id,
            prompt,
            decode: &self.decode,
            seed,
        })?;
        let mut st = self.stats.lock().expect("stats");
        st.calls += 1;
        st.receipts += reply.receipt.is_some() as u64;
        st.settled += reply.settlement.as_ref().is_some_and(|s| !s.is_null()) as u64;
        if let Some(c) = &reply.cost_wei {
            st.cost_wei += c
                .parse::<u128>()
                .map_err(|e| format!("cost_wei {c}: {e}"))?;
        }
        drop(st);
        Ok(Entry {
            action: parse_answer(obs.role, &reply.text)
                .map(|i| obs.role.menu()[i].0.to_string())
                .unwrap_or_else(|| "invalid".into()),
            raw: reply.text,
            model_id: self.model.id.clone(),
            model_hash: self.model.hash.clone(),
            template: self.template.version().into(),
            role: obs.role.name().into(),
            hour: obs.hour,
            receipt: reply.receipt,
            cost_wei: reply.cost_wei,
            settlement: reply.settlement,
            input_tokens: reply.input_tokens,
            output_tokens: reply.output_tokens,
        })
    }
}

/// The menu index an answer names: its first word, lowercased, without
/// punctuation, must be an action of the role's menu.
pub fn parse_answer(role: Role, text: &str) -> Option<usize> {
    let word: String = text
        .split_whitespace()
        .next()?
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase();
    role.parse(&word)
}

impl DecisionPolicy for ModelPolicy {
    fn name(&self) -> String {
        format!(
            "model:{}:{}:{}",
            self.model.id,
            self.template.version(),
            self.mode.name()
        )
    }

    fn decide(&self, run_seed: u64, obs: &Observation) -> Result<Action, String> {
        let seed = decision_seed(run_seed, obs.role, obs.agent, obs.hour);
        let canonical = obs.canonical();
        let key = cache_key(&self.model, self.template, &canonical, &self.decode, seed);
        let cached = self.cache.lock().expect("cache").entries.get(&key).cloned();
        let (entry, hit) = match (cached, self.mode) {
            (Some(e), _) => (e, true),
            (None, Mode::Record) => {
                let prompt = self.template.render(obs);
                let e = self.ask(&prompt, seed, obs)?;
                self.cache
                    .lock()
                    .expect("cache")
                    .entries
                    .insert(key.clone(), e.clone());
                (e, false)
            }
            (None, m) => {
                return Err(format!(
                    "{}: no cached answer for {} agent {} at hour {} (key {key})",
                    m.name(),
                    obs.role.name(),
                    obs.agent,
                    obs.hour
                ));
            }
        };
        if let Mode::LiveProbe { per_mille } = self.mode
            && sampled(&key, per_mille)
        {
            let live = self.ask(&self.template.render(obs), seed, obs)?;
            let mut st = self.stats.lock().expect("stats");
            st.probed += 1;
            if live.action == entry.action {
                st.agreed += 1;
            } else if st.disagreements.len() < 50 {
                st.disagreements
                    .push((key.clone(), entry.action.clone(), live.action));
            }
        }
        let index = obs.role.parse(&entry.action);
        let mut st = self.stats.lock().expect("stats");
        st.decisions += 1;
        st.hits += hit as u64;
        st.recorded += (!hit) as u64;
        st.invalid += index.is_none() as u64;
        *st.actions
            .entry(format!("{}:{}", obs.role.name(), entry.action))
            .or_default() += 1;
        Ok(Action {
            role: obs.role,
            index: index.unwrap_or(obs.current),
        })
    }
}

/// Whether `key` is in the live-probe sample.
fn sampled(key: &str, per_mille: u32) -> bool {
    let n = u32::from_str_radix(&key[..4], 16).unwrap_or(0) % 1000;
    n < per_mille
}

/// Sends requests through the `tenzro` command line, which signs with the
/// identity of its namespace: `tenzro rpc call tenzro_chat` on the serving
/// node, paying through a channel whose next cumulative voucher the agent's
/// serving node signs (`tenzro_agentVoucher`). Each voucher covers what the
/// channel has spent plus `ceiling_wei`.
pub struct CliTransport {
    /// The `tenzro` executable.
    pub cli: PathBuf,
    /// RPC of the node that serves the model.
    pub rpc: String,
    /// Payment channel, when calls are paid.
    pub channel: Option<Channel>,
    spent: Mutex<u128>,
}

/// A payment channel the agent's wallet funded.
#[derive(Debug, Clone)]
pub struct Channel {
    /// RPC of the agent's serving node, which signs its vouchers.
    pub agent_rpc: String,
    /// Channel id, hex.
    pub channel_id: String,
    /// Most one call may cost, wei.
    pub ceiling_wei: u128,
    /// What the channel had spent before this run, wei.
    pub spent_wei: u128,
}

impl CliTransport {
    /// A transport through `cli` to `rpc`.
    pub fn new(cli: PathBuf, rpc: String, channel: Option<Channel>) -> Self {
        let spent = channel.as_ref().map(|c| c.spent_wei).unwrap_or(0);
        CliTransport {
            cli,
            rpc,
            channel,
            spent: Mutex::new(spent),
        }
    }

    fn call(
        &self,
        rpc: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let out = std::process::Command::new(&self.cli)
            .args(["rpc", "call", method, "--rpc", rpc, "--params"])
            .arg(params.to_string())
            .output()
            .map_err(|e| format!("{}: {e}", self.cli.display()))?;
        if !out.status.success() {
            return Err(format!(
                "{method}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        serde_json::from_slice(&out.stdout).map_err(|e| format!("{method} reply: {e}"))
    }
}

impl Transport for CliTransport {
    fn complete(&self, req: &Request<'_>) -> Result<Reply, String> {
        // One call at a time: each voucher builds on what the last spent.
        let mut spent = self.spent.lock().expect("spent");
        let mut params = serde_json::json!({
            "model_id": req.model_id,
            "messages": [{ "role": "user", "content": req.prompt }],
            "max_tokens": req.decode.max_tokens,
            "temperature": req.decode.temperature,
            "top_p": req.decode.top_p,
            "stop": req.decode.stop,
            "seed": req.seed,
        });
        if let Some(c) = &self.channel {
            let v = self.call(
                &c.agent_rpc,
                "tenzro_agentVoucher",
                &serde_json::json!({
                    "channel_id": c.channel_id,
                    "cumulative_amount": (*spent + c.ceiling_wei).to_string(),
                }),
            )?;
            params["channel_voucher"] = v
                .get("voucher")
                .cloned()
                .ok_or("tenzro_agentVoucher returned no voucher")?;
        }
        let r = self.call(&self.rpc, "tenzro_chat", &params)?;
        let cost_wei = r.get("cost_wei").and_then(|v| v.as_str()).map(String::from);
        if self.channel.is_some() {
            let c: u128 = cost_wei
                .as_deref()
                .ok_or("paid call returned no cost")?
                .parse()
                .map_err(|e| format!("cost_wei: {e}"))?;
            *spent += c;
        }
        Ok(Reply {
            text: r
                .get("output")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            receipt: r.get("tenzro_receipt").cloned().filter(|v| !v.is_null()),
            cost_wei,
            settlement: r.get("settlement").cloned(),
            input_tokens: r.get("input_tokens").and_then(|v| v.as_u64()),
            output_tokens: r.get("output_tokens").and_then(|v| v.as_u64()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs() -> Observation {
        Observation {
            role: Role::Provider,
            agent: 2,
            hour: 168,
            current: 1,
            state: [("price_q", -7), ("week", 1)].into_iter().collect(),
        }
    }

    #[test]
    fn canonical_state_is_sorted_and_integer() {
        assert_eq!(
            obs().canonical(),
            r#"{"current":"list","price_q":-7,"role":"provider","week":1}"#
        );
    }

    #[test]
    fn the_key_covers_every_input() {
        let m = ModelRef {
            id: "m".into(),
            hash: "ab".repeat(32),
        };
        let d = Decode::default();
        let s = obs().canonical();
        let k = cache_key(&m, Template::Lines1, &s, &d, 7);
        let m2 = ModelRef {
            hash: "cd".repeat(32),
            ..m.clone()
        };
        let d2 = Decode {
            temperature: 0.7,
            ..d.clone()
        };
        for other in [
            cache_key(&m2, Template::Lines1, &s, &d, 7),
            cache_key(&m, Template::Json1, &s, &d, 7),
            cache_key(&m, Template::Lines1, "{}", &d, 7),
            cache_key(&m, Template::Lines1, &s, &d2, 7),
            cache_key(&m, Template::Lines1, &s, &d, 8),
        ] {
            assert_ne!(k, other);
        }
        assert_ne!(
            decision_seed(1, Role::Buyer, 0, 0),
            decision_seed(1, Role::Buyer, 1, 0)
        );
    }

    #[test]
    fn answers_outside_the_menu_are_invalid() {
        assert_eq!(parse_answer(Role::Provider, " Premium."), Some(2));
        assert_eq!(parse_answer(Role::Provider, "undercut\nbecause"), Some(0));
        assert_eq!(parse_answer(Role::Provider, "raise prices"), None);
        assert_eq!(parse_answer(Role::Provider, ""), None);
    }

    #[test]
    fn replay_misses_fail_and_a_hand_written_entry_replays() {
        let m = ModelRef {
            id: "m".into(),
            hash: "ab".repeat(32),
        };
        let d = Decode::default();
        let o = obs();
        let p = ModelPolicy::new(
            m.clone(),
            Template::Lines1,
            d.clone(),
            Mode::Replay,
            Cache::default(),
            None,
        )
        .expect("policy");
        assert!(p.decide(5, &o).is_err());
        let key = cache_key(
            &m,
            Template::Lines1,
            &o.canonical(),
            &d,
            decision_seed(5, o.role, o.agent, o.hour),
        );
        let mut c = Cache {
            version: 1,
            ..Cache::default()
        };
        c.entries.insert(
            key,
            Entry {
                action: "premium".into(),
                raw: "premium".into(),
                model_id: "m".into(),
                model_hash: m.hash.clone(),
                template: "lines-1".into(),
                role: "provider".into(),
                hour: 168,
                receipt: None,
                cost_wei: None,
                settlement: None,
                input_tokens: None,
                output_tokens: None,
            },
        );
        let h = c.manifest_hash();
        let p = ModelPolicy::new(m, Template::Lines1, d, Mode::Replay, c, None).expect("policy");
        assert_eq!(p.decide(5, &o).expect("hit").name(), "premium");
        assert_eq!(p.cache().manifest_hash(), h);
        assert!(
            ModelPolicy::new(
                ModelRef {
                    id: "z".into(),
                    hash: "0".repeat(64)
                },
                Template::Lines1,
                Decode::default(),
                Mode::Replay,
                Cache::default(),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn every_template_names_every_action() {
        for t in Template::ALL {
            for role in Role::ALL {
                let o = Observation {
                    role,
                    current: role.default_action(),
                    ..obs()
                };
                let s = t.render(&o);
                for (w, _) in role.menu() {
                    assert!(s.contains(w), "{} {}", t.version(), w);
                }
            }
        }
    }
}
