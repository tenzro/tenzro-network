//! Tempo network integration
//!
//! Provides direct integration with the Tempo blockchain for
//! stablecoin settlement, MPP batch settlement, and cross-chain bridging.

pub mod config;
pub mod adapter;
pub mod stablecoin;
pub mod participant;

pub use config::{TempoConfig, TEMPO_CHAIN_ID, TEMPO_MAINNET_RPC, TEMPO_TESTNET_RPC};
pub use adapter::TempoBridgeAdapter;
pub use stablecoin::{Tip20Token, Tip20Balance};
pub use participant::TempoParticipant;
