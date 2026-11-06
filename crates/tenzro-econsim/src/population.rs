//! Population market traces: machines and agents trading services over a
//! span of hours, in a named scenario.
//!
//! Every actor carries a price, a capacity, a reliability, an honesty, a
//! budget and working hours, all drawn from the seed:
//!
//! - a provider (a machine selling a service) asks its price per job, serves
//!   at most its capacity of jobs per hour, delivers a paid job with
//!   probability its reliability while honest, and spends its budget on
//!   peers when more jobs come than its capacity holds;
//! - a buyer (an agent) pays at most its price per job, wants about its
//!   capacity of jobs per hour while it works, is online for its reliability
//!   share of its working time and stops when its budget is spent; a
//!   dishonest buyer pays a provider of its own, which claims every job
//!   delivered, to make volume.
//!
//! A buyer keeps a few providers it knows, takes the cheapest one online with
//! room this hour, and drops a provider that failed to deliver to it. Any
//! provider whose public record shows more recent failures than deliveries
//! is passed over. When none it knows will do it looks at a sample of the
//! others.
//!
//! Scenarios ([`Scenario`]): `calm`; `outage`, a fifth of the providers off
//! for the middle third of the span; `defect`, 15% of the providers keeping
//! the payments and delivering nothing from a quarter of the span on;
//! `surge`, demand five times over in the middle third; `reprice`, at half
//! the span 30% of the providers doubling their price and 30% cutting it by
//! 40%; `stress`, the outage and the surge together; `adversarial`, 10% of
//! the providers dishonest from the start and 5% of the buyers paying
//! providers of their own. The population is the seed's in every scenario;
//! only what happens to it differs.
//!
//! The trace is JSON lines sorted by time: a `# market-trace {..}` header,
//! then one payment per line, `t_ms`, `buyer` (the payer), `provider` (the
//! payee), `service`, `amount_milli` and `delivered`. [`crate::trace`] reads
//! it as demand; the network simulator replays it as transfers. One seed and
//! one scenario always give the same bytes.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt::Write as _;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// What happens to the population over the span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scenario {
    /// Nothing but the population's own behaviour.
    Calm,
    /// A fifth of the providers off for the middle third of the span.
    Outage,
    /// 15% of the providers stop delivering from a quarter of the span on.
    Defect,
    /// Demand five times over for the middle third of the span.
    Surge,
    /// At half the span 30% of the providers double their price and 30% cut it by 40%.
    Reprice,
    /// The outage and the surge at once.
    Stress,
    /// 10% of the providers dishonest from the start, 5% of the buyers
    /// paying providers of their own.
    Adversarial,
}

impl Scenario {
    /// Every scenario, in the order the population stage runs the first five.
    pub const ALL: [Scenario; 7] = [
        Scenario::Calm,
        Scenario::Outage,
        Scenario::Defect,
        Scenario::Surge,
        Scenario::Reprice,
        Scenario::Stress,
        Scenario::Adversarial,
    ];

    /// The scenario named `s`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }

    /// Its name.
    pub fn name(self) -> &'static str {
        match self {
            Scenario::Calm => "calm",
            Scenario::Outage => "outage",
            Scenario::Defect => "defect",
            Scenario::Surge => "surge",
            Scenario::Reprice => "reprice",
            Scenario::Stress => "stress",
            Scenario::Adversarial => "adversarial",
        }
    }

    fn outage(self) -> bool {
        matches!(self, Scenario::Outage | Scenario::Stress)
    }

    fn surge(self) -> bool {
        matches!(self, Scenario::Surge | Scenario::Stress)
    }
}

/// The services sold, with the base price of a job in thousandths.
pub const SERVICES: [(&str, f64); 4] = [
    ("compute", 400.0),
    ("inference", 120.0),
    ("storage", 30.0),
    ("search", 15.0),
];

/// Share of the actors that are providers.
const PROVIDER_SHARE: f64 = 0.12;
/// Share of the providers dishonest in every scenario.
const BASE_DISHONEST: f64 = 0.01;
/// Providers a buyer keeps.
const KNOWN: usize = 3;
/// Providers a buyer looks at when none it knows will do.
const SAMPLE: usize = 6;
/// Demand over the base in a surge.
const SURGE: f64 = 5.0;

/// One run's settings.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PopulationConfig {
    /// Seed of the population and of what happens to it.
    pub seed: u64,
    /// Actors, providers and buyers together (at least 20).
    pub actors: u32,
    /// Span, hours.
    pub hours: f64,
    /// What happens over the span.
    pub scenario: Scenario,
}

/// One actor.
#[derive(Debug, Clone, Serialize)]
pub struct Actor {
    /// Number in the trace.
    pub id: u32,
    /// Sells (`true`) or buys.
    pub provider: bool,
    /// Index into [`SERVICES`].
    pub service: usize,
    /// Asked (provider) or paid at most (buyer) per job, thousandths.
    pub price_milli: f64,
    /// Jobs per hour served (provider) or wanted while working (buyer).
    pub capacity_per_hour: f64,
    /// Share of paid jobs delivered (provider) or of working time online (buyer).
    pub reliability: f64,
    /// Delivers what it is paid for (provider) or buys only what it needs (buyer).
    pub honest: bool,
    /// Most it spends over the span, thousandths.
    pub budget_milli: f64,
    /// Hour of the day its working hours start (the span starts at hour 0).
    pub start_hour: f64,
    /// Length of its working hours.
    pub working_hours: f64,
    /// The provider a dishonest buyer pays.
    pub accomplice: Option<u32>,
}

impl Actor {
    fn working(&self, t_ms: u64) -> bool {
        let h = (t_ms as f64 / 3_600_000.0 + 24.0 - self.start_hour) % 24.0;
        h < self.working_hours
    }
}

/// One payment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Payment {
    /// Millisecond from the start of the span.
    pub t_ms: u64,
    /// Payer.
    pub buyer: u32,
    /// Payee.
    pub provider: u32,
    /// Index into [`SERVICES`].
    pub service: usize,
    /// Thousandths.
    pub amount_milli: u64,
    /// The job was delivered (as the payee claims, for a dishonest pair).
    pub delivered: bool,
}

/// What a run did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PopulationStats {
    /// Providers.
    pub providers: u32,
    /// Buyers.
    pub buyers: u32,
    /// Payments.
    pub payments: u64,
    /// Payments for a job not delivered.
    pub undelivered: u64,
    /// Payments between a dishonest buyer and its accomplice.
    pub wash: u64,
    /// Payments from a provider to a peer for a job it had no room for.
    pub subcontracted: u64,
    /// Jobs wanted that no provider took (none online, with room, within the price).
    pub unserved: u64,
    /// Buyers that spent their budget before the end.
    pub budget_spent: u64,
    /// Providers a buyer dropped after a job not delivered.
    pub dropped: u64,
    /// Sum of the payments, thousandths.
    pub value_milli: u64,
}

/// A generated trace.
#[derive(Debug, Clone)]
pub struct Population {
    /// Settings.
    pub config: PopulationConfig,
    /// The actors, by number.
    pub actors: Vec<Actor>,
    /// The payments, by time.
    pub payments: Vec<Payment>,
    /// Counts.
    pub stats: PopulationStats,
}

/// A stable 64-bit mix (splitmix64), so streams derived from the seed do not
/// depend on the standard library's hasher.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn stream(seed: u64, name: &str) -> StdRng {
    let mut h = mix(seed);
    for b in name.bytes() {
        h = mix(h ^ u64::from(b));
    }
    StdRng::seed_from_u64(h)
}

/// exp(N(mu, sigma)).
fn lognormal(rng: &mut StdRng, mu: f64, sigma: f64) -> f64 {
    let u1: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
    (mu + sigma * z).exp()
}

fn exponential(rng: &mut StdRng, rate: f64) -> f64 {
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
    -u.ln() / rate
}

/// The seed's population: the same in every scenario.
pub fn actors(seed: u64, n: u32) -> Vec<Actor> {
    let mut rng = stream(seed, "actors");
    let providers = ((f64::from(n) * PROVIDER_SHARE).round() as u32).max(SERVICES.len() as u32 * 2);
    // Providers are spread through the numbering, not first.
    let mut is_provider = vec![false; n as usize];
    let mut placed = 0;
    while placed < providers {
        let i = rng.gen_range(0..n) as usize;
        if !is_provider[i] {
            is_provider[i] = true;
            placed += 1;
        }
    }
    let mut out = Vec::with_capacity(n as usize);
    let mut k = 0usize;
    for (id, &p) in is_provider.iter().enumerate() {
        // Every service has providers: the first ones cycle through them.
        let service = if p && k < SERVICES.len() * 2 {
            k % SERVICES.len()
        } else {
            // Compute and inference make most of the demand.
            match rng.gen_range(0.0..1.0) {
                x if x < 0.35 => 0,
                x if x < 0.75 => 1,
                x if x < 0.90 => 2,
                _ => 3,
            }
        };
        let base = SERVICES[service].1;
        let a = if p {
            k += 1;
            let capacity = lognormal(&mut rng, 3.0, 0.6).clamp(4.0, 400.0);
            let price = base * lognormal(&mut rng, 0.0, 0.35);
            Actor {
                id: id as u32,
                provider: true,
                service,
                price_milli: price,
                capacity_per_hour: capacity,
                reliability: 1.0 - lognormal(&mut rng, -4.0, 0.9).min(0.4),
                honest: rng.gen_range(0.0..1.0) >= BASE_DISHONEST,
                // About a tenth of an hour's work at capacity, bought from peers.
                budget_milli: price * capacity * rng.gen_range(0.05..0.3),
                // Machines mostly run around the clock.
                start_hour: rng.gen_range(0.0..24.0),
                working_hours: if rng.gen_range(0.0..1.0) < 0.8 {
                    24.0
                } else {
                    rng.gen_range(8.0..20.0)
                },
                accomplice: None,
            }
        } else {
            let ceiling = base * lognormal(&mut rng, 0.35, 0.3);
            let rate = lognormal(&mut rng, -0.4, 0.8).clamp(0.05, 30.0);
            Actor {
                id: id as u32,
                provider: false,
                service,
                price_milli: ceiling,
                capacity_per_hour: rate,
                reliability: rng.gen_range(0.6..1.0),
                honest: true,
                // From a fraction of an hour's wants to many hours' worth.
                budget_milli: ceiling * rate * lognormal(&mut rng, 0.7, 0.9),
                start_hour: rng.gen_range(0.0..24.0),
                working_hours: rng.gen_range(6.0..18.0),
                accomplice: None,
            }
        };
        out.push(a);
    }
    out
}

/// Per provider during a run.
#[derive(Clone, Default)]
struct Book {
    hour: u64,
    used: f64,
    jobs: u64,
    /// Share of recent jobs not delivered, about the last five.
    failing: f64,
    spent: f64,
    off: Option<(u64, u64)>,
    defect_at: Option<u64>,
    reprice_at: Option<(u64, f64)>,
}

impl Book {
    /// Its public record shows more recent failures than deliveries.
    fn poor(&self) -> bool {
        self.jobs >= 5 && self.failing > 0.5
    }
}

/// Per buyer during a run.
#[derive(Clone, Default)]
struct Wallet {
    spent: f64,
    known: Vec<u32>,
    dropped: Vec<u32>,
    done: bool,
}

/// Generates the trace of `config`.
pub fn generate(config: PopulationConfig) -> Result<Population, String> {
    if config.actors < 20 {
        return Err(format!("at least 20 actors, not {}", config.actors));
    }
    if !(config.hours > 0.0 && config.hours <= 24.0 * 365.0) {
        return Err(format!("hours must be in (0, 8760], not {}", config.hours));
    }
    let span_ms = (config.hours * 3_600_000.0) as u64;
    let mut actors = actors(config.seed, config.actors);
    let mut rng = stream(config.seed, config.scenario.name());
    let providers: Vec<u32> = actors.iter().filter(|a| a.provider).map(|a| a.id).collect();
    let by_service: Vec<Vec<u32>> = (0..SERVICES.len())
        .map(|s| {
            providers
                .iter()
                .copied()
                .filter(|&p| actors[p as usize].service == s)
                .collect()
        })
        .collect();
    let mut books: Vec<Book> = vec![Book::default(); actors.len()];

    // What the scenario does to the providers.
    let sc = config.scenario;
    for &p in &providers {
        let b = &mut books[p as usize];
        let draw: f64 = rng.gen_range(0.0..1.0);
        if sc.outage() && draw < 0.20 {
            b.off = Some((span_ms / 3, span_ms * 2 / 3));
        }
        if sc == Scenario::Defect && (0.20..0.35).contains(&draw) {
            b.defect_at = Some(span_ms / 4);
        }
        if sc == Scenario::Adversarial && (0.20..0.30).contains(&draw) {
            actors[p as usize].honest = false;
        }
        if sc == Scenario::Reprice {
            if draw < 0.30 {
                b.reprice_at = Some((span_ms / 2, 2.0));
            } else if draw < 0.60 {
                b.reprice_at = Some((span_ms / 2, 0.6));
            }
        }
    }
    // Dishonest buyers each with a provider of their own.
    if sc == Scenario::Adversarial {
        for i in 0..actors.len() {
            if actors[i].provider || rng.gen_range(0.0..1.0) >= 0.05 {
                continue;
            }
            let pool = &by_service[actors[i].service];
            let p = pool[rng.gen_range(0..pool.len())];
            actors[i].honest = false;
            actors[i].accomplice = Some(p);
            actors[p as usize].honest = false;
            // Volume is the point: several times an honest buyer's rate.
            actors[i].capacity_per_hour *= 4.0;
        }
    }

    let price = |a: &Actor, b: &Book, t: u64| match b.reprice_at {
        Some((at, f)) if t >= at => a.price_milli * f,
        _ => a.price_milli,
    };
    let demand = |t: u64| {
        if sc.surge() && t >= span_ms / 3 && t < span_ms * 2 / 3 {
            SURGE
        } else {
            1.0
        }
    };
    let peak = if sc.surge() { SURGE } else { 1.0 };

    // Each buyer's candidate jobs at its peak rate, thinned to its rate at the time.
    let mut wallets: Vec<Wallet> = vec![Wallet::default(); actors.len()];
    let mut queue: BinaryHeap<Reverse<(u64, u32)>> = BinaryHeap::new();
    let mut job_rng: Vec<StdRng> = Vec::with_capacity(actors.len());
    for a in &actors {
        let mut r = stream(config.seed ^ mix(u64::from(a.id) + 1), sc.name());
        if !a.provider {
            let first = exponential(&mut r, a.capacity_per_hour * peak / 3_600_000.0);
            if first < span_ms as f64 {
                queue.push(Reverse((first as u64, a.id)));
            }
            let w = &mut wallets[a.id as usize];
            let pool = &by_service[a.service];
            while w.known.len() < KNOWN.min(pool.len()) {
                let p = pool[r.gen_range(0..pool.len())];
                if !w.known.contains(&p) {
                    w.known.push(p);
                }
            }
        }
        job_rng.push(r);
    }

    let mut stats = PopulationStats {
        providers: providers.len() as u32,
        buyers: config.actors - providers.len() as u32,
        ..PopulationStats::default()
    };
    let mut payments = Vec::new();

    // Room at `p` this hour: takes one job if there is.
    let take = |b: &mut Book, a: &Actor, t: u64| -> bool {
        let hour = t / 3_600_000;
        if b.hour != hour {
            b.hour = hour;
            b.used = 0.0;
        }
        if b.used + 1.0 > a.capacity_per_hour {
            return false;
        }
        b.used += 1.0;
        true
    };
    let online = |b: &Book, a: &Actor, t: u64| {
        a.working(t) && !b.off.is_some_and(|(from, to)| t >= from && t < to)
    };

    while let Some(Reverse((t, id))) = queue.pop() {
        let i = id as usize;
        // The next candidate job of this buyer.
        let peak_rate = actors[i].capacity_per_hour * peak / 3_600_000.0;
        let next = t as f64 + exponential(&mut job_rng[i], peak_rate).max(1.0);
        let r = &mut job_rng[i];
        let wants = r.gen_range(0.0..1.0) < demand(t) / peak
            && actors[i].working(t)
            && r.gen_range(0.0..1.0) < actors[i].reliability;
        if wants && !wallets[i].done {
            let buyer = &actors[i];
            if let Some(p) = buyer.accomplice {
                // A payment to its own provider, claimed delivered.
                let amount = price(&actors[p as usize], &books[p as usize], t);
                if wallets[i].spent + amount > buyer.budget_milli {
                    wallets[i].done = true;
                    stats.budget_spent += 1;
                } else {
                    wallets[i].spent += amount;
                    stats.wash += 1;
                    payments.push(Payment {
                        t_ms: t,
                        buyer: id,
                        provider: p,
                        service: buyer.service,
                        amount_milli: amount.round().max(1.0) as u64,
                        delivered: true,
                    });
                }
            } else {
                // The cheapest provider it knows that is online, within its price and has room.
                let ceiling = buyer.price_milli;
                let mut pick: Option<(f64, u32)> = None;
                let mut known = std::mem::take(&mut wallets[i].known);
                known.retain(|p| !wallets[i].dropped.contains(p));
                for &p in &known {
                    let (pa, pb) = (&actors[p as usize], &books[p as usize]);
                    let ask = price(pa, pb, t);
                    if online(pb, pa, t)
                        && !pb.poor()
                        && ask <= ceiling
                        && pick.is_none_or(|(c, _)| ask < c)
                    {
                        pick = Some((ask, p));
                    }
                }
                let mut chosen = None;
                // The cheapest first; one with no room passes to the next.
                let mut tried: Vec<u32> = Vec::new();
                while let Some((_, p)) = pick {
                    let (pa, pb) = (&actors[p as usize], &mut books[p as usize]);
                    if take(pb, pa, t) {
                        chosen = Some(p);
                        break;
                    }
                    tried.push(p);
                    pick = None;
                    for &q in &known {
                        let (qa, qb) = (&actors[q as usize], &books[q as usize]);
                        let ask = price(qa, qb, t);
                        if !tried.contains(&q)
                            && online(qb, qa, t)
                            && !qb.poor()
                            && ask <= ceiling
                            && pick.is_none_or(|(c, _)| ask < c)
                        {
                            pick = Some((ask, q));
                        }
                    }
                }
                // A full provider passes the job to a peer it pays, while its budget lasts.
                let mut sub: Option<u32> = None;
                if chosen.is_none()
                    && let Some(&full) = tried.first()
                {
                    let pool = &by_service[buyer.service];
                    for _ in 0..SAMPLE {
                        let q = pool[r.gen_range(0..pool.len())];
                        let (qa, qb) = (&actors[q as usize], &books[q as usize]);
                        if q != full && online(qb, qa, t) && !qb.poor() {
                            let cost = price(qa, qb, t);
                            if books[full as usize].spent + cost
                                <= actors[full as usize].budget_milli
                                && take(&mut books[q as usize], &actors[q as usize], t)
                            {
                                books[full as usize].spent += cost;
                                chosen = Some(full);
                                sub = Some(q);
                                break;
                            }
                        }
                    }
                }
                // None it knows will do: a look at others, skipping a poor public record.
                if chosen.is_none() {
                    let pool = &by_service[buyer.service];
                    let mut best: Option<(f64, u32)> = None;
                    for _ in 0..SAMPLE {
                        let q = pool[r.gen_range(0..pool.len())];
                        let (qa, qb) = (&actors[q as usize], &books[q as usize]);
                        let ask = price(qa, qb, t);
                        if !qb.poor()
                            && !wallets[i].dropped.contains(&q)
                            && !known.contains(&q)
                            && online(qb, qa, t)
                            && ask <= ceiling
                            && best.is_none_or(|(c, _)| ask < c)
                        {
                            best = Some((ask, q));
                        }
                    }
                    if let Some((_, q)) = best
                        && take(&mut books[q as usize], &actors[q as usize], t)
                    {
                        chosen = Some(q);
                        if known.len() >= KNOWN {
                            known.remove(0);
                        }
                        known.push(q);
                    }
                }
                wallets[i].known = known;
                match chosen {
                    None => stats.unserved += 1,
                    Some(p) => {
                        let amount = price(&actors[p as usize], &books[p as usize], t);
                        if wallets[i].spent + amount > buyer.budget_milli {
                            // Spent: it stops buying, and the room it was given goes unused.
                            wallets[i].done = true;
                            stats.budget_spent += 1;
                        } else {
                            wallets[i].spent += amount;
                            let pa = &actors[p as usize];
                            let defected = books[p as usize].defect_at.is_some_and(|d| t >= d);
                            // A subcontracted job is delivered as the peer delivers it.
                            let deliverer = sub.unwrap_or(p);
                            let da = &actors[deliverer as usize];
                            let dd = books[deliverer as usize].defect_at.is_some_and(|d| t >= d);
                            let delivered = pa.honest
                                && !defected
                                && da.honest
                                && !dd
                                && r.gen_range(0.0..1.0) < da.reliability;
                            let b = &mut books[p as usize];
                            b.jobs += 1;
                            b.failing = 0.8 * b.failing + if delivered { 0.0 } else { 0.2 };
                            if !delivered {
                                stats.undelivered += 1;
                                wallets[i].dropped.push(p);
                                wallets[i].known.retain(|&k| k != p);
                                stats.dropped += 1;
                            }
                            payments.push(Payment {
                                t_ms: t,
                                buyer: id,
                                provider: p,
                                service: buyer.service,
                                amount_milli: amount.round().max(1.0) as u64,
                                delivered,
                            });
                            if let Some(q) = sub {
                                let cost = price(&actors[q as usize], &books[q as usize], t);
                                stats.subcontracted += 1;
                                payments.push(Payment {
                                    t_ms: t,
                                    buyer: p,
                                    provider: q,
                                    service: buyer.service,
                                    amount_milli: cost.round().max(1.0) as u64,
                                    delivered,
                                });
                            }
                        }
                    }
                }
            }
        }
        if (next as u64) < span_ms && !wallets[i].done {
            queue.push(Reverse((next as u64, id)));
        }
    }
    stats.payments = payments.len() as u64;
    stats.value_milli = payments.iter().map(|p| p.amount_milli).sum();
    Ok(Population {
        config,
        actors,
        payments,
        stats,
    })
}

impl Population {
    /// The trace's text: the header line, then one payment per line.
    pub fn trace(&self) -> String {
        let mut out = String::with_capacity(self.payments.len() * 96 + 256);
        let header = serde_json::json!({
            "seed": self.config.seed,
            "actors": self.config.actors,
            "hours": self.config.hours,
            "scenario": self.config.scenario.name(),
            "providers": self.stats.providers,
            "buyers": self.stats.buyers,
            "unit": "amount_milli is thousandths of the payment unit",
        });
        let _ = writeln!(out, "# market-trace {header}");
        for p in &self.payments {
            let _ = writeln!(
                out,
                "{{\"t_ms\":{},\"buyer\":{},\"provider\":{},\"service\":\"{}\",\"amount_milli\":{},\"delivered\":{}}}",
                p.t_ms, p.buyer, p.provider, SERVICES[p.service].0, p.amount_milli, p.delivered
            );
        }
        out
    }

    /// SHA-256 of the trace's text, hex.
    pub fn digest(text: &str) -> String {
        hex::encode(Sha256::digest(text.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(seed: u64, actors: u32, scenario: Scenario) -> Population {
        generate(PopulationConfig {
            seed,
            actors,
            hours: 2.0,
            scenario,
        })
        .expect("generates")
    }

    /// Payments to honest buyers' providers (not the dishonest pairs') in [from, to) of the span.
    fn between(p: &Population, from: f64, to: f64) -> Vec<&Payment> {
        let span = p.config.hours * 3_600_000.0;
        p.payments
            .iter()
            .filter(|x| (x.t_ms as f64) >= from * span && (x.t_ms as f64) < to * span)
            .collect()
    }

    #[test]
    fn one_seed_gives_the_same_trace_and_another_seed_another() {
        for s in Scenario::ALL {
            let a = run(11, 3_000, s).trace();
            let b = run(11, 3_000, s).trace();
            assert_eq!(
                Population::digest(&a),
                Population::digest(&b),
                "{}",
                s.name()
            );
            assert_ne!(a, run(12, 3_000, s).trace(), "{}", s.name());
        }
        // The population is the seed's whatever the scenario.
        let calm = actors(11, 3_000);
        let surge = run(11, 3_000, Scenario::Surge).actors;
        assert_eq!(calm.len(), surge.len());
        assert!(
            calm.iter()
                .zip(&surge)
                .all(|(a, b)| a.price_milli == b.price_milli
                    && a.budget_milli == b.budget_milli
                    && a.capacity_per_hour == b.capacity_per_hour)
        );
    }

    #[test]
    fn the_trace_is_sorted_well_formed_and_read_as_demand() {
        let p = run(5, 4_000, Scenario::Calm);
        assert!(p.payments.windows(2).all(|w| w[0].t_ms <= w[1].t_ms));
        assert!(p.payments.iter().all(|x| x.buyer != x.provider
            && x.buyer < 4_000
            && x.provider < 4_000
            && x.amount_milli > 0
            && x.t_ms < 7_200_000));
        let text = p.trace();
        assert!(text.starts_with("# market-trace {"));
        let d = crate::trace::TraceDemand::parse("pop", &text, 1.0).expect("parses");
        assert_eq!(d.payments, p.stats.payments);
        assert!(d.delivered_share > 0.9, "{}", d.delivered_share);
        assert!(d.service_share.len() == SERVICES.len());
        // Every actor carries its five traits within their ranges.
        for a in &p.actors {
            assert!(a.price_milli > 0.0 && a.capacity_per_hour > 0.0 && a.budget_milli > 0.0);
            assert!((0.0..=1.0).contains(&a.reliability));
        }
    }

    #[test]
    fn no_buyer_spends_past_its_budget_and_no_provider_past_its_capacity() {
        for s in [Scenario::Calm, Scenario::Surge, Scenario::Adversarial] {
            let p = run(3, 4_000, s);
            let mut spent = vec![0u64; 4_000];
            // Jobs served in an hour: those paid for, less those passed to a peer.
            let mut per_hour: std::collections::BTreeMap<(u32, u64), i64> = Default::default();
            for x in &p.payments {
                spent[x.buyer as usize] += x.amount_milli;
                *per_hour
                    .entry((x.provider, x.t_ms / 3_600_000))
                    .or_default() += 1;
                if p.actors[x.buyer as usize].provider {
                    *per_hour.entry((x.buyer, x.t_ms / 3_600_000)).or_default() -= 1;
                }
            }
            for a in &p.actors {
                // Rounding each payment to a thousandth can add half of one per payment.
                let n = p.payments.iter().filter(|x| x.buyer == a.id).count() as f64;
                assert!(
                    spent[a.id as usize] as f64 <= a.budget_milli + n * 0.5 + 1.0,
                    "{} {}",
                    s.name(),
                    a.id
                );
            }
            for ((prov, _), n) in per_hour {
                let a = &p.actors[prov as usize];
                if a.honest {
                    assert!(
                        n as f64 <= a.capacity_per_hour,
                        "{} provider {prov} served {n}",
                        s.name()
                    );
                }
            }
        }
    }

    #[test]
    fn a_surge_multiplies_demand_in_the_middle_third() {
        let calm = run(7, 6_000, Scenario::Calm);
        let surge = run(7, 6_000, Scenario::Surge);
        let (c, s) = (
            between(&calm, 0.34, 0.66).len(),
            between(&surge, 0.34, 0.66).len(),
        );
        assert!(s as f64 > 2.5 * c as f64, "calm {c} surge {s}");
        // Capacity and budgets hold some of it back.
        assert!(surge.stats.unserved > 2 * calm.stats.unserved.max(1));
        let (c0, s0) = (
            between(&calm, 0.0, 0.3).len(),
            between(&surge, 0.0, 0.3).len(),
        );
        assert!(
            (s0 as f64) < 1.3 * c0 as f64 && (s0 as f64) > 0.7 * c0 as f64,
            "{c0} {s0}"
        );
    }

    #[test]
    fn providers_in_an_outage_are_paid_nothing_while_off() {
        let p = run(9, 6_000, Scenario::Outage);
        let paid_mid: std::collections::BTreeSet<u32> =
            between(&p, 0.34, 0.66).iter().map(|x| x.provider).collect();
        let paid_before: std::collections::BTreeSet<u32> =
            between(&p, 0.0, 0.33).iter().map(|x| x.provider).collect();
        // About a fifth of the providers paid before are not paid while off.
        let gone = paid_before.difference(&paid_mid).count() as f64 / paid_before.len() as f64;
        assert!(gone > 0.12, "{gone}");
        let calm = run(9, 6_000, Scenario::Calm);
        let calm_mid: std::collections::BTreeSet<u32> = between(&calm, 0.34, 0.66)
            .iter()
            .map(|x| x.provider)
            .collect();
        let calm_before: std::collections::BTreeSet<u32> = between(&calm, 0.0, 0.33)
            .iter()
            .map(|x| x.provider)
            .collect();
        let calm_gone = calm_before.difference(&calm_mid).count() as f64 / calm_before.len() as f64;
        assert!(gone > calm_gone + 0.08, "outage {gone} calm {calm_gone}");
    }

    #[test]
    fn buyers_leave_providers_that_stop_delivering() {
        let p = run(13, 6_000, Scenario::Defect);
        let calm = run(13, 6_000, Scenario::Calm);
        let undelivered = |v: Vec<&Payment>| {
            v.iter().filter(|x| !x.delivered).count() as f64 / v.len().max(1) as f64
        };
        let early = undelivered(between(&p, 0.0, 0.25));
        let onset = undelivered(between(&p, 0.25, 0.45));
        let late = undelivered(between(&p, 0.8, 1.0));
        assert!(
            onset > 3.0 * early.max(0.005),
            "early {early} onset {onset}"
        );
        // Once burned, buyers move on: the share falls back.
        assert!(late < onset * 0.6, "onset {onset} late {late}");
        assert!(p.stats.dropped > 2 * calm.stats.dropped);
    }

    #[test]
    fn a_repricing_moves_buyers_and_the_mean_price() {
        let p = run(17, 6_000, Scenario::Reprice);
        let calm = run(17, 6_000, Scenario::Calm);
        let mean = |v: Vec<&Payment>| {
            v.iter().map(|x| x.amount_milli as f64).sum::<f64>() / v.len().max(1) as f64
        };
        let before = mean(between(&p, 0.0, 0.5)) / mean(between(&calm, 0.0, 0.5));
        let after = mean(between(&p, 0.5, 1.0)) / mean(between(&calm, 0.5, 1.0));
        assert!((before - 1.0).abs() < 0.02, "{before}");
        // The cheaper ones take the buyers the dearer ones lost.
        assert!(after < 0.97, "{after}");
    }

    #[test]
    fn adversaries_wash_volume_and_cheats_lose_their_buyers() {
        let p = run(19, 6_000, Scenario::Adversarial);
        assert!(p.stats.wash > 200, "{}", p.stats.wash);
        let washers = p.actors.iter().filter(|a| a.accomplice.is_some()).count();
        assert!(washers > 100, "{washers}");
        // Honest buyers' payments to dishonest providers fall as they are found out.
        let cheated = |v: Vec<&Payment>| {
            v.iter()
                .filter(|x| {
                    p.actors[x.buyer as usize].honest && !p.actors[x.provider as usize].honest
                })
                .count()
        };
        let (early, late) = (
            cheated(between(&p, 0.0, 0.2)),
            cheated(between(&p, 0.8, 1.0)),
        );
        assert!(late * 2 < early, "early {early} late {late}");
    }

    #[test]
    fn scenario_names_and_bad_settings() {
        for s in Scenario::ALL {
            assert_eq!(Scenario::parse(s.name()), Some(s));
        }
        assert_eq!(Scenario::parse("sunny"), None);
        let c = |actors, hours| PopulationConfig {
            seed: 1,
            actors,
            hours,
            scenario: Scenario::Calm,
        };
        assert!(generate(c(10, 2.0)).is_err());
        assert!(generate(c(100, 0.0)).is_err());
    }
}
