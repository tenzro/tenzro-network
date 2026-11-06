//! Kani proof harnesses for the ledger, governance, slashing, insurance,
//! training challenge bond, settlement-reward and bridge-limit arithmetic.
//! Built only under `cargo kani --features kani`:
//!
//! ```text
//! cargo kani -p tenzro-vm --features kani -Z function-contracts -Z stubbing
//! ```
//!
//! Products and quotients of wide symbolic values are proved as small lemmas
//! in harnesses marked `kani::solver(cvc5)`, which need cvc5 to reason about
//! bit-vectors as integers (`--solve-bv-as-int=sum`, for example through a
//! `cvc5` wrapper earlier on `PATH`). The harnesses that compose them replace
//! the lemma functions by their contracts (`kani::stub_verified`) or by a
//! model that assumes exactly what the lemma harnesses prove (`kani::stub`).
//!
//! Each harness proves a property for every input of its type, not for
//! samples. Where a property spans a sequence of operations, the harness
//! proves it inductively: from any state that satisfies the invariant, any
//! one operation leads to a state that still satisfies it.

mod bridge;
mod governance;
mod insurance;
mod ledger;
mod rewards;
mod slashing;
mod training;
