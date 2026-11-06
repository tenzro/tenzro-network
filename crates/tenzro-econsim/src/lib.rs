//! Economic simulation of the network's token economy.
//!
//! Populations of people with wallets, delegated agents renting compute,
//! providers with compute bonds and SLA behaviour, and validators with
//! running costs transact on the simulated ledger
//! ([`tenzro_sim::ledger::Ledger`]), so fees, settlement, rewards, staking,
//! slashing, the insurance pool, treasury grants and governed parameters
//! are the VM's own code, not a model of it.
//!
//! On top of the populations:
//! - multi-year scenarios (growth, flat, downturn) over many seeds;
//! - a Morris screen and Sobol indices over governed parameters and
//!   behaviour assumptions, with the range of each parameter where runs
//!   keep their invariants;
//! - adversaries searched for profitable strategies;
//! - spam at real block time;
//! - ablations: each mechanism of the design switched off alone, and a
//!   cartel sweep against the rate's quantile band;
//! - machine-economy models with no human trading.
//! - rewards paid on settlements against wash and collusion, and the cheat
//!   penalty across payment size and price.
//! - the running-cost reserve from a zero or tiny seed across adoption
//!   levels, a revenue drought and a price crash.
//! - the closed phase before a public listing, and the day its listing
//!   gate is met.
//! - payments settled in a stable token on the ledger, with the treasury
//!   leg taken in TNZO or in the token, and a governed treasury sell-back.
//! - population market traces: machines and agents with their own price,
//!   capacity, reliability, honesty, budget and working hours, in calm and
//!   disturbed scenarios, for the network simulator to replay.
//! - combined and correlated shocks over decades, many seeds, with the
//!   invariants each run keeps ([`chaos`]).
//!
//! The TNZO price is the price of a thin pool the populations trade on:
//! agents buy what they pay with, providers, validators and grantees sell,
//! and outside trading is zero-mean.
//!
//! Demand, outside trading and operators' costs are inputs with ranges, not
//! predictions. The report says what each result depends on.

pub mod ablation;
pub mod admission;
pub mod attack;
pub mod bme;
pub mod campaign;
pub mod chain;
pub mod chaos;
pub mod classes;
pub mod crash;
pub mod decision;
pub mod device_classes;
pub mod dex;
pub mod earnings;
pub mod economy;
pub mod growth;
pub mod gsa;
pub mod hardware_levels;
pub mod listing;
pub mod machine;
pub mod population;
pub mod probes;
pub mod report;
pub mod research;
pub mod search;
pub mod settlement_rewards;
pub mod spam;
pub mod stable;
pub mod staking;
pub mod trace;
pub mod treasury;
pub mod usage;
pub mod usage_fixtures;
pub mod usage_lw;
