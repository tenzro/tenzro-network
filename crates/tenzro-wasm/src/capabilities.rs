//! Capability declarations for sandboxed WASI components.
//!
//! A WASI 0.2 component starts with **no** ambient authority: no
//! filesystem, no network, no environment variables, no system clock
//! beyond the deterministic clock the host provides. Hosts grant
//! capabilities explicitly through a [`SkillCapabilities`] value
//! attached to the [`crate::manifest::ComponentManifest`].
//!
//! Capabilities are additive — every grant widens the surface the
//! component can touch. Unset capability lists deny everything by
//! default; this is the secure default for community-supplied code.

use serde::{Deserialize, Serialize};

/// Storage capabilities the host may grant to a component.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageCapability {
    /// Read-only mounts of host directories under guest-visible paths.
    /// Mounts use the WASI 0.2 `preopens` model — each pair is
    /// `(host_path, guest_path)`.
    #[serde(default)]
    pub read_only: Vec<(String, String)>,

    /// Read-write mounts. Same semantics as `read_only`.
    #[serde(default)]
    pub read_write: Vec<(String, String)>,
}

/// Network capabilities the host may grant to a component.
///
/// Allow-lists are matched against the destination host (DNS name or
/// IP). An empty list means "no outbound network." Wildcard matching
/// is `prefix:*` (e.g. `api.tenzro.xyz`, `*.tenzro.xyz`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkCapability {
    /// Hosts the component may open outbound TCP connections to.
    #[serde(default)]
    pub outbound_tcp: Vec<String>,

    /// Hosts the component may resolve via DNS.
    #[serde(default)]
    pub dns_allow: Vec<String>,

    /// Whether the component may open outbound HTTPS streams via the
    /// host-exported `tenzro:net/https` interface. This is the
    /// preferred way for skills to fetch remote data — it lets the
    /// host audit every URL.
    #[serde(default)]
    pub https_proxy: bool,
}

/// Aggregate capability declaration for a component.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillCapabilities {
    /// Storage capabilities.
    #[serde(default)]
    pub storage: StorageCapability,

    /// Network capabilities.
    #[serde(default)]
    pub network: NetworkCapability,

    /// Environment variables the host may expose to the component.
    /// Variables not in this list are not visible to the guest.
    #[serde(default)]
    pub env: Vec<String>,

    /// Tenzro host-interface methods the component may invoke
    /// (see [`crate::HostInterface`]). Examples: `wallet.read_balance`,
    /// `inference.embed`, `events.publish`. Unrecognized names are
    /// rejected at load time so misconfigured manifests fail closed.
    #[serde(default)]
    pub host_methods: Vec<String>,
}

impl SkillCapabilities {
    /// The maximally-restrictive policy: no I/O, no host interfaces.
    /// Used as the default when a manifest omits the field entirely.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// A common "pure compute" policy — no I/O, but the component may
    /// publish events back to the host and read its skill's own
    /// configuration. Useful for forecasting / embedding / scoring skills
    /// that don't need network access.
    pub fn pure_compute() -> Self {
        Self {
            storage: StorageCapability::default(),
            network: NetworkCapability::default(),
            env: Vec::new(),
            host_methods: vec![
                "config.read".into(),
                "events.publish".into(),
                "metrics.observe".into(),
            ],
        }
    }

    /// Returns `true` if the manifest's `host_methods` list contains
    /// `method`.
    pub fn allows_host_method(&self, method: &str) -> bool {
        self.host_methods.iter().any(|m| m == method)
    }
}
