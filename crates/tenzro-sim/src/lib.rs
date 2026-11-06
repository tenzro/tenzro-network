//! Deterministic network simulator.
//!
//! Every validator runs the consensus core ([`tenzro_consensus::Core`]) and
//! every ordered block runs through the VM's block rules
//! ([`ledger::Ledger`]), on one simulated clock over a simulated network. A
//! run follows entirely from its seed, so any failure replays exactly.
//!
//! Faults are injected from the seed: crashes and restarts from the
//! recovery journal, downtimes longer than the window peers keep, partitions
//! with and without a surviving quorum, delay spikes, frame loss, clock
//! offsets, and byzantine validators within `f`. Clients run value
//! transfers, governance proposals carried to enactment, validators joining
//! by bonding, unbonding and withdrawing, bond top-ups and equivocation
//! evidence that slashes, over a calendar that genesis may run faster than
//! block time, so years of epochs pass in hours.
//!
//! Invariants checked while the run goes:
//! - safety: one content per height, one certificate per checkpoint, one
//!   committee per epoch, no validator proposing twice in a round;
//! - liveness: commits and certificates advance within a bound whenever a
//!   quorum of honest validators is up and connected;
//! - memory and storage: every validator's consensus state, recovery
//!   journal and block store stay under caps and do not grow over the run;
//! - value: every block meets the ledger's value rule and all balances sum
//!   to the recorded supply;
//! - rejoin: a restarted or newly seated validator reaches the network's
//!   epoch and height within a bound of live network;
//! - execution: every validator writes each block to its own block store
//!   and reads it back through the node's codec before executing it; a
//!   block it cannot read stops it, as it stops a node;
//! - ordering: senders routed to their batching validator rarely run a
//!   transaction ahead of its nonce while the one before it is in flight
//!   (such a transaction goes back to the mempool, as in the node, and
//!   runs when ordered again), within a bound of all sent;
//! - leaders: no slot of an honest, up, connected leader is skipped while
//!   the network has been calm for a while;
//! - signing: no honest validator signs two checkpoints with one index,
//!   across restarts.
//!
//! Next to the protocol core and the ledger runs the node layer
//! ([`node`]): block building, the block store and its codec, transaction
//! routing through the node's own routing function, senders keeping
//! several transactions in flight, disk stalls and slow validators. The
//! node's transport and block sync are not in the loop: a validator further
//! behind than the certificates peers keep is modelled as syncing the
//! certified chain.
//!
//! A run can stop injecting faults part way and run healed for the rest,
//! so recovery is judged once faults stop. `swarm` draws every setting from
//! the seed, and the explorer runs seed after seed within a time budget,
//! printing each failure with the command that replays it.

pub mod config;
pub mod ledger;
pub mod node;
pub mod report;
pub mod trace;
pub mod world;

pub use config::SimConfig;
pub use report::Report;
pub use world::World;

/// Runs one configuration to the end.
pub fn run(cfg: SimConfig, progress: impl FnMut(&Report)) -> Report {
    World::new(cfg).run(progress)
}

/// Runs one configuration to the end with extra client drivers (for example
/// a recorded population, see [`trace`]).
pub fn run_with_drivers(
    cfg: SimConfig,
    drivers: Vec<Box<dyn world::ClientDriver>>,
    progress: impl FnMut(&Report),
) -> Report {
    let mut world = World::new(cfg);
    for d in drivers {
        world = world.with_driver(d);
    }
    world.run(progress)
}

/// Measures the cost of verifying one composite validator signature, in
/// microseconds, on this machine.
pub fn measure_verify_us(samples: u32) -> u64 {
    use tenzro_consensus::ValidatorSigner;
    let key = tenzro_consensus::validator_key::test_signer::SoftwareTestSigner::from_seed(42);
    let msg = [7u8; 32];
    let sig = key.sign(b"tenzro/sim/measure", &msg).expect("sign");
    let pk = key.public_key().clone();
    let t = std::time::Instant::now();
    let mut ok = 0u32;
    for _ in 0..samples.max(1) {
        if pk.verify(b"tenzro/sim/measure", &msg, &sig) {
            ok += 1;
        }
    }
    assert_eq!(ok, samples.max(1), "signature verifies");
    (t.elapsed().as_micros() as u64 / samples.max(1) as u64).max(1)
}
