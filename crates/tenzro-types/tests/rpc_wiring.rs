//! Release check, wiring: every method the node dispatches has a named binding
//! on every client surface (CLI command, Rust MCP tool, Python MCP tool, TS
//! SDK method, Rust SDK method, Python SDK method), or is listed in [`NODE_INTERNAL`] with the
//! reason no client binding belongs to it.
//!
//! A binding is the method's name quoted in that surface's source: each
//! surface reaches the node by naming the method it calls. The universal
//! by-name gateway (`surface_parity_integration`) is the floor; this test
//! holds the named bindings.

#[path = "support/gate.rs"]
mod gate;

use std::collections::{BTreeMap, BTreeSet};

/// Client surfaces: (name, source directories, file extensions).
const SURFACES: &[(&str, &[&str], &[&str])] = &[
    ("cli", &["crates/tenzro-cli/src"], &[".rs"]),
    ("mcp-rust", &["crates/tenzro-node/src/mcp"], &[".rs"]),
    (
        "sdk-ts",
        &["sdk/tenzro-ts-sdk/src", "sdk/tenzro-ts-sdk/packages"],
        &[".ts"],
    ),
    ("sdk-rust", &["sdk/tenzro-sdk/src"], &[".rs"]),
    ("sdk-python", &["sdk/tenzro-py/tenzro"], &[".py"]),
];

/// Methods with no client binding: (exact name, or a prefix ending in `_`,
/// reason). Every entry must match at least one dispatched method.
const NODE_INTERNAL: &[(&str, &str)] = &[
    (
        "tenzro_getHandoverChain",
        "node to node: a restoring node (tenzro-node restore --proof-from) and a prover's input export (tenzro-node prover-inputs) read it",
    ),
    (
        "eth_",
        "Ethereum JSON-RPC namespace served to EVM wallets and libraries; those clients are its surface",
    ),
    (
        "net_",
        "Ethereum JSON-RPC namespace served to EVM wallets and libraries",
    ),
    (
        "web3_",
        "Ethereum JSON-RPC namespace served to EVM wallets and libraries",
    ),
    (
        "getAccountInfo",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getBalance",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getBlockHeight",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getFeeForMessage",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getHealth",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getLatestBlockhash",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getMinimumBalanceForRentExemption",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getSignatureStatuses",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getSlot",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "getVersion",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "isBlockhashValid",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "sendTransaction",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
    (
        "simulateTransaction",
        "Solana JSON-RPC method served to Solana wallets and libraries; those clients are its surface",
    ),
];

/// Methods bound on some surfaces only: (exact name, surfaces it has no
/// binding on, reason). Every entry must name a dispatched method.
const SURFACE_EXEMPT: &[(&str, &[&str], &str)] = &[
    (
        "tenzro_transcribeStream",
        &["cli", "sdk-ts", "sdk-rust"],
        "the CLI and these SDKs stream live audio over POST /tenzro/realtime/transcribe, the same transcription, and show each event as it arrives; the method is the whole-recording form for tool callers",
    ),
    (
        "tenzro_priceCardToPublish",
        &["mcp-rust"],
        "builds the registry entry for the node operator's own card, which only the operator account can sign and put (tenzro provider pricing post); a tool caller reads published cards with get_price_card",
    ),
    (
        "tenzro_refreshToken",
        &["mcp-rust"],
        "refuses any Authorization header and wants a DPoP proof over its own request; an MCP client refreshes the token its session uses at this server's OAuth token endpoint (grant_type=refresh_token), and the Rust MCP tool for it was removed when refresh became key-bound",
    ),
];

fn exempt(method: &str, surface: &str) -> bool {
    SURFACE_EXEMPT
        .iter()
        .any(|(m, s, _)| *m == method && s.contains(&surface))
}

fn internal(method: &str) -> bool {
    NODE_INTERNAL.iter().any(|(m, _)| {
        if m.ends_with('_') {
            method.starts_with(m)
        } else {
            method == *m
        }
    })
}

fn surface_names() -> Vec<(&'static str, BTreeSet<String>)> {
    let methods = gate::rpc_methods();
    SURFACES
        .iter()
        .map(|(name, dirs, exts)| {
            // A literal naming a dispatched method counts even when its verb is
            // one lowercase word (`tenzro_chat`), which the shape test skips.
            let names = gate::files(dirs, exts)
                .iter()
                .flat_map(|(p, t)| {
                    let rust = p.ends_with(".rs");
                    let mut found = gate::rpc_names_in(p, &gate::before_tests(t));
                    found.extend(
                        gate::before_tests(t)
                            .lines()
                            .flat_map(|l| gate::quoted(l, rust))
                            .filter(|s| methods.contains(s)),
                    );
                    found
                })
                .collect();
            (*name, names)
        })
        .collect()
}

#[test]
fn every_dispatched_method_is_wired_on_every_surface() {
    let methods = gate::rpc_methods();
    let surfaces = surface_names();
    let mut missing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for m in &methods {
        if internal(m) {
            continue;
        }
        for (name, names) in &surfaces {
            if !names.contains(m) && !exempt(m, name) {
                missing.entry(m.as_str()).or_default().push(name);
            }
        }
    }
    let mut per_surface: BTreeMap<&str, usize> = BTreeMap::new();
    for s in missing.values().flatten() {
        *per_surface.entry(s).or_default() += 1;
    }
    let lines: Vec<String> = missing
        .iter()
        .map(|(m, s)| format!("{m}: {}", s.join(", ")))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {} dispatched methods lack a binding (per surface: {per_surface:?}); wire them or list them in NODE_INTERNAL with a reason:\n  {}",
        missing.len(),
        methods.len(),
        lines.join("\n  ")
    );
}

#[test]
fn every_node_internal_entry_names_a_dispatched_method() {
    let methods = gate::rpc_methods();
    let stale: Vec<&str> = NODE_INTERNAL
        .iter()
        .map(|(m, _)| *m)
        .filter(|m| {
            !methods.iter().any(|d| {
                if m.ends_with('_') {
                    d.starts_with(m)
                } else {
                    d == m
                }
            })
        })
        .collect();
    assert!(
        stale.is_empty(),
        "NODE_INTERNAL names methods the node does not serve: {stale:?}"
    );
}

#[test]
fn every_surface_exemption_names_a_dispatched_method_and_a_surface() {
    let methods = gate::rpc_methods();
    let surfaces: Vec<&str> = SURFACES.iter().map(|(n, _, _)| *n).collect();
    for (m, s, _) in SURFACE_EXEMPT {
        assert!(
            methods.contains(*m),
            "SURFACE_EXEMPT names {m}, which the node does not serve"
        );
        for surface in *s {
            assert!(
                surfaces.contains(surface),
                "SURFACE_EXEMPT names unknown surface {surface} for {m}"
            );
        }
    }
}

#[test]
fn the_name_reader_sees_known_bindings() {
    let surfaces = surface_names();
    for (name, names) in &surfaces {
        assert!(
            names.len() > 50,
            "{name}: only {} method names read; the reader is broken",
            names.len()
        );
    }
    assert!(gate::is_rpc_name("tenzro_iroh_getConfig"));
    assert!(gate::is_rpc_name("eth_chainId"));
    assert!(!gate::is_rpc_name("tenzro_mcp_server"));
}
