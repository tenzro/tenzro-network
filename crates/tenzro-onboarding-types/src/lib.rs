//! Onboarding gate rules and update state shared by the node, the network layer and the CLI.
//!
//! These types live outside tenzro-types so the finality guest source (which hashes tenzro-types) stays unchanged.

#![deny(missing_docs)]

pub mod onboarding;
pub mod update_state;
