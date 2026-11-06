//! The finality program: one light-client step over a Tenzro checkpoint
//! certificate. It reads a [`FinalityStep`], verifies it, and commits the
//! journal of what it proved; it commits nothing for a step that does not
//! verify.

use std::io::Read;

use risc0_zkvm::guest::env;
use tenzro_finality::step::FinalityStep;

fn main() {
    let mut input = Vec::new();
    env::stdin().read_to_end(&mut input).expect("the step is readable");
    let step: FinalityStep = bincode::deserialize(&input).expect("the step decodes");
    let journal = step.verify().expect("the step verifies");
    env::commit_slice(&journal.encode());
}
