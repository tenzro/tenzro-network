//! The handover program: one link of the epoch handover chain. It reads a
//! [`HandoverLink`], verifies the proof the link builds on (a receipt of this
//! same program, which the prover supplies as an assumption), verifies the
//! link, and commits the journal of the chain with the link added; it commits
//! nothing for a link that does not verify.

use std::io::Read;

use risc0_zkvm::guest::env;
use tenzro_finality::chain::HandoverLink;

fn main() {
    let mut input = Vec::new();
    env::stdin().read_to_end(&mut input).expect("the link is readable");
    let link: HandoverLink = bincode::deserialize(&input).expect("the link decodes");
    if let Some(prev) = &link.prev {
        env::verify(prev.program, &prev.encode()).expect("the previous link is proven");
    }
    let journal = link.verify().expect("the link verifies");
    env::commit_slice(&journal.encode());
}
