//! Network contract suite: one test per node-to-node path, each run over
//! every route of a four-node in-process cluster (direct, NAT-only,
//! outbound-only and relay-only nodes behind a local test relay).
//!
//! A test passes only when its path works on every route a node can be
//! reached by. The discovery, acceptance and reachability tests sign endpoint
//! records with machine keys in the host TPM (run via the node-live stage).
//!
//! Unix only: a cluster's machine keys are held by the host TPM or by a
//! provider reached through a key holder's Unix socket, and a Windows build
//! host's own TPM is never used by tests. The suite runs on the Linux build
//! hosts.
//!
//! `cargo test -p tenzro-node --test network_contract`
#![cfg(unix)]

mod cluster;
mod endpoint_paths;
mod pending;
mod point_to_point;
