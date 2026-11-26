//! The Tenzro Assistant: the operator's helper built into the node tooling.
//!
//! It runs as the person who started `tenzro`, on their own machine. A slash
//! command names one tool from the registry; anything else is a question
//! answered from the documentation shipped in this binary. A tool that only
//! reads runs at once. A tool that changes the machine, or needs the
//! operator's key, never runs on the assistant's word: `tenzro do` shows the
//! exact command and stops, and the console shows it and runs it on the
//! person's own terminal only after they press y.

pub mod chat;
pub mod knowledge;
pub mod local;
pub mod model;
pub mod reply;
pub mod router;
pub mod tools;
