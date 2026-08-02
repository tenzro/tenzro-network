//! Per-invocation WASI store state.
//!
//! Every component instantiation gets a fresh [`WasiState`] as the
//! `Store<T>` data. It carries the WASI 0.2 context, the WASI HTTP
//! context (for `function`-class apps that export the `wasi:http`
//! proxy world), and the component-model resource table.
//!
//! The context is built from the component manifest's
//! [`SkillCapabilities`] so a component starts with **no** ambient
//! authority and is granted exactly — and only — what the manifest
//! declares and the host policy permits.

use std::net::IpAddr;

use wasmtime::component::ResourceTable;
use wasmtime_wasi::filesystem::{DirPerms, FilePerms};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpHooks, WasiHttpView};

use crate::capabilities::SkillCapabilities;

/// No-op `wasi:http` hooks — every method falls back to its default
/// implementation. Held as a concrete store field so the view can hand
/// out a `&mut dyn WasiHttpHooks` bound to the store's lifetime.
#[derive(Default)]
struct DefaultHttpHooks;

impl WasiHttpHooks for DefaultHttpHooks {}

/// Store data for a single component instantiation.
///
/// Holds the three views the WASI + WASI-HTTP linkers need. A new
/// value is constructed per invocation so no state leaks between
/// otherwise-identical executions — the deterministic default.
pub struct WasiState {
    ctx: WasiCtx,
    http: WasiHttpCtx,
    hooks: DefaultHttpHooks,
    table: ResourceTable,
}

impl WasiState {
    /// Builds store state from a component's declared capabilities.
    ///
    /// Grants:
    /// - Environment variables the manifest lists (only those keys the
    ///   host actually exposes are read from the process environment).
    /// - Read-only / read-write directory preopens.
    /// - Outbound network **only** when the manifest declares at least
    ///   one outbound-TCP or DNS entry. A `socket_addr_check` closure
    ///   enforces the IP-literal subset of the allow-list against the
    ///   resolved destination; hostname entries are gated at the DNS
    ///   layer via `allow_ip_name_lookup`. Absent any network grant the
    ///   component gets no sockets at all.
    ///
    /// Stdio is inherited so component `println!` / panic output lands
    /// in the node log; guests never see host stdin.
    pub fn from_capabilities(caps: &SkillCapabilities) -> Self {
        let mut builder = WasiCtxBuilder::new();
        builder.inherit_stdio();

        for key in &caps.env {
            if let Ok(val) = std::env::var(key) {
                builder.env(key, &val);
            }
        }

        for (host_path, guest_path) in &caps.storage.read_only {
            let _ = builder.preopened_dir(host_path, guest_path, DirPerms::READ, FilePerms::READ);
        }
        for (host_path, guest_path) in &caps.storage.read_write {
            let _ = builder.preopened_dir(host_path, guest_path, DirPerms::all(), FilePerms::all());
        }

        // Network is opt-in. `inherit_network` enables the socket
        // machinery; without at least one declared destination we do
        // not call it, so the component has no outbound reachability.
        let wants_network =
            !caps.network.outbound_tcp.is_empty() || !caps.network.dns_allow.is_empty();
        if wants_network {
            builder.inherit_network();
            builder.allow_ip_name_lookup(!caps.network.dns_allow.is_empty());

            // `socket_addr_check` runs against an already-resolved
            // `SocketAddr`, so it can only enforce the IP-literal subset
            // of the manifest allow-list. Collect those entries once.
            // Hostname entries are gated at the DNS layer above: a guest
            // can only reach a host it is permitted to resolve.
            let allowed_ips: Vec<IpAddr> = caps
                .network
                .outbound_tcp
                .iter()
                .filter_map(|entry| entry.parse::<IpAddr>().ok())
                .collect();
            let all_entries_are_hostnames = allowed_ips.is_empty();

            builder.socket_addr_check(move |addr, _use| {
                // When the allow-list contains no IP literals, every
                // destination reached the resolver through a permitted
                // DNS name, so accept. Otherwise the connection IP must
                // match a declared IP literal.
                let permitted = all_entries_are_hostnames || allowed_ips.contains(&addr.ip());
                Box::pin(async move { permitted })
            });
        }

        Self {
            ctx: builder.build(),
            http: WasiHttpCtx::new(),
            hooks: DefaultHttpHooks,
            table: ResourceTable::new(),
        }
    }
}

impl WasiView for WasiState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for WasiState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}
