//! Tempo network integration
//!
//! Provides direct integration with the Tempo blockchain for
//! stablecoin settlement, MPP batch settlement, and cross-chain bridging.

pub mod adapter;
pub mod config;
pub mod participant;
pub mod stablecoin;

pub use adapter::TempoBridgeAdapter;
pub use config::{TEMPO_CHAIN_ID, TEMPO_MAINNET_RPC, TEMPO_TESTNET_RPC, TempoConfig};
pub use participant::TempoParticipant;
pub use stablecoin::{Tip20Balance, Tip20Token};
