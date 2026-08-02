//! Machine hosting: unmodified long-lived server processes run inside a
//! hardware-isolated Firecracker microVM on a capability-gated node, reached
//! over the same `tenzro/http` ingress path that static sites and functions use.
//!
//! A `machine` app is the runtime class for code that a `function` cannot be:
//! a resident process with cross-request state, a listening socket, arbitrary
//! syscalls — an unmodified Node / Python / Rust server. The only honest way to
//! run such code with real isolation is a microVM, so a machine deployment
//! targets a node that advertises the `machine` capability (Linux with
//! `/dev/kvm`, root / `CAP_NET_ADMIN` for tap networking, jailer for isolation).
//! Nodes without that capability still hold the deployment metadata but never
//! run the microVM; ingress answers a machine request with 501 there.
//!
//! A deployment records the content-addressed microVM image (a BLAKE3 CAID in
//! the iroh store), the loopback port the guest server listens on
//! (`internal_port`), a resource envelope, and any sealed environment secrets.
//! Records persist under `CF_METADATA` keyed `machine:<id>` with write-through
//! on deploy / remove and hydrate-on-boot, matching the site and function
//! registries.
//!
//! The naming layer is shared with [`crate::sites::SiteRegistry`] and
//! [`crate::functions::FunctionRegistry`]: the same
//! `compute_site_id(owner_did, name)` derives the id, and the same alias /
//! custom-domain tables resolve a public Host header to that id. A given id is a
//! static site, a function, or a machine — never more than one.
//!
//! # Sealed secrets (spec §4.3 item 7)
//!
//! Environment secrets never appear in the deployment metadata as plaintext.
//! The deployer wraps each secret to the assigned node's X25519 sealing key with
//! [`tenzro_crypto::encryption::envelope_encrypt`] (X25519 + AES-256-GCM); the
//! registry stores the resulting envelope bytes opaquely. The supervisor
//! decrypts them at microVM launch inside the node's enclave via
//! [`tenzro_crypto::encryption::envelope_decrypt`], and the plaintext exists
//! only in guest memory. The registry itself never sees a decrypted secret.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_METADATA, KvStore};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::sites::compute_site_id;

/// Key prefix for machine deployment records within `CF_METADATA`.
const MACHINE_PREFIX: &str = "machine:";

fn machine_key(id: &str) -> Vec<u8> {
    format!("{MACHINE_PREFIX}{id}").into_bytes()
}

const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum MachineError {
    #[error("invalid deployment: {0}")]
    InvalidDeployment(String),
    #[error("machine not found: {0}")]
    NotFound(String),
    #[error("not machine owner")]
    NotOwner,
    #[error("machine runtime unavailable on this node")]
    RuntimeUnavailable,
    #[error("supervisor error: {0}")]
    Supervisor(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Resource envelope the microVM is provisioned with. The scheduler hard-filters
/// placement bids against a node's advertised free capacity; the supervisor
/// passes these to the Firecracker machine config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineResources {
    /// Guest vCPU count.
    pub vcpus: u32,
    /// Guest memory in mebibytes.
    pub mem_mib: u32,
    /// Root-filesystem budget in mebibytes (the image is copied into a
    /// jailer-scoped writable overlay of this size).
    pub disk_mib: u32,
}

impl Default for MachineResources {
    fn default() -> Self {
        Self {
            vcpus: 1,
            mem_mib: 256,
            disk_mib: 1024,
        }
    }
}

/// Unprivileged uid the jailer drops each microVM to by default. Running
/// firecracker as a non-root host user means a guest-to-host escape lands on an
/// account with no privileges rather than root. Operators reserve a dedicated
/// system account for this and override via
/// [`MachineSupervisor::with_jailer_identity`].
pub const DEFAULT_JAILER_UID: u32 = 30000;
/// Unprivileged gid the jailer drops each microVM to by default.
pub const DEFAULT_JAILER_GID: u32 = 30000;
/// cgroup version the jailer uses for per-microVM resource accounting. `2` is
/// the unified hierarchy present on current kernels; operators on legacy hosts
/// override to `1`.
pub const DEFAULT_JAILER_CGROUP_VERSION: u8 = 2;
/// Seccomp filter level firecracker installs on itself. `2` is firecracker's
/// advanced per-thread syscall allow-list; `0` disables filtering (not
/// recommended). The jailer forwards this to firecracker.
pub const DEFAULT_JAILER_SECCOMP_LEVEL: u8 = 2;

/// A single sealed environment secret. `name` is the plaintext variable name
/// (not secret); `sealed_value` is the `EncryptedEnvelope` (X25519 + AES-256-GCM)
/// wrapped to the assigned node's sealing key, JSON-serialized. The supervisor
/// unwraps it at launch inside the enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvVar {
    pub name: String,
    /// JSON-serialized [`tenzro_crypto::encryption::EncryptedEnvelope`].
    pub sealed_value: serde_json::Value,
}

/// A deployed machine app: the microVM image plus how to run and reach it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineDeployment {
    /// Deterministic id from `compute_site_id(owner_did, name)`. Shared naming
    /// space with static sites and functions so aliases / custom domains resolve
    /// uniformly.
    pub id: String,
    pub name: String,
    pub owner_did: String,
    pub version: u64,
    /// BLAKE3 hex (64 lowercase hex chars) of the microVM image in the iroh
    /// store — a bootable root filesystem plus a kernel reference.
    pub artifact_caid: String,
    /// The loopback port the guest server listens on. Ingress bridges each
    /// forwarded raw-HTTP stream to `127.0.0.1:<internal_port>` in the guest.
    pub internal_port: u16,
    /// Resource envelope for the microVM.
    pub resources: MachineResources,
    /// Sealed environment secrets injected at launch (decrypted in-enclave).
    #[serde(default)]
    pub sealed_env: Vec<SealedEnvVar>,
    /// When true, the microVM must run inside a TEE (SEV-SNP / TDX); placement
    /// is restricted to nodes advertising both `machine` and `tee`.
    #[serde(default)]
    pub tee_required: bool,
    /// TNZO per request; when `Some`, serving is x402-gated.
    pub price_per_request: Option<u128>,
    pub created_at: u64,
    pub updated_at: u64,
}

fn validate_name(name: &str) -> Result<(), MachineError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(MachineError::InvalidDeployment(
            "name must be 1-64 characters".into(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(MachineError::InvalidDeployment(
            "name may only contain [a-zA-Z0-9._-]".into(),
        ));
    }
    Ok(())
}

fn validate_caid(caid: &str) -> Result<(), MachineError> {
    if caid.len() != 64
        || !caid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(MachineError::InvalidDeployment(
            "artifact_caid must be 64 lowercase hex chars".into(),
        ));
    }
    Ok(())
}

fn validate_resources(r: &MachineResources) -> Result<(), MachineError> {
    if r.vcpus == 0 || r.vcpus > 32 {
        return Err(MachineError::InvalidDeployment("vcpus must be 1-32".into()));
    }
    if r.mem_mib < 64 || r.mem_mib > 131_072 {
        return Err(MachineError::InvalidDeployment(
            "mem_mib must be 64-131072".into(),
        ));
    }
    if r.disk_mib < 64 || r.disk_mib > 1_048_576 {
        return Err(MachineError::InvalidDeployment(
            "disk_mib must be 64-1048576".into(),
        ));
    }
    Ok(())
}

/// Registry of deployed machine apps with write-through persistence. The live
/// microVM supervisor lives on the node under the `firecracker` feature; this
/// registry holds only the durable metadata so the deploy / list / get / remove
/// RPCs work on any node regardless of whether it can run the microVM.
pub struct MachineRegistry {
    machines: DashMap<String, MachineDeployment>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for MachineRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineRegistry")
            .field("machines", &self.machines.len())
            .finish()
    }
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self {
            machines: DashMap::new(),
            storage: None,
        }
    }

    /// Storage-backed registry: hydrates existing deployments from `CF_METADATA`
    /// under the `machine:` prefix.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self, MachineError> {
        let registry = Self {
            machines: DashMap::new(),
            storage: Some(storage.clone()),
        };
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, MACHINE_PREFIX.as_bytes())
            .map_err(|e| MachineError::Storage(format!("machine scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<MachineDeployment>(&bytes) {
                    Ok(deployment) => {
                        registry.machines.insert(deployment.id.clone(), deployment);
                        restored += 1;
                    }
                    Err(e) => warn!("skipping undecodable machine deployment: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(MachineError::Storage(format!("machine get: {e}"))),
            }
        }
        if restored > 0 {
            info!("restored {restored} machine deployment(s)");
        }
        Ok(registry)
    }

    fn persist(&self, deployment: &MachineDeployment) -> Result<(), MachineError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(deployment)
                .map_err(|e| MachineError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &machine_key(&deployment.id), &bytes)
                .map_err(|e| MachineError::Storage(format!("machine put: {e}")))?;
        }
        Ok(())
    }

    /// Deploy or redeploy a machine app. Redeploying the same (owner, name) bumps
    /// `version` and preserves `created_at`; a different owner is rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn deploy(
        &self,
        name: &str,
        owner_did: &str,
        artifact_caid: &str,
        internal_port: u16,
        resources: MachineResources,
        sealed_env: Vec<SealedEnvVar>,
        tee_required: bool,
        price_per_request: Option<u128>,
    ) -> Result<MachineDeployment, MachineError> {
        validate_name(name)?;
        if !owner_did.starts_with("did:") {
            return Err(MachineError::InvalidDeployment(
                "owner_did must be a DID".into(),
            ));
        }
        validate_caid(artifact_caid)?;
        validate_resources(&resources)?;
        if internal_port == 0 {
            return Err(MachineError::InvalidDeployment(
                "internal_port must be non-zero".into(),
            ));
        }

        let id = compute_site_id(owner_did, name);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let deployment = match self.machines.get(&id) {
            Some(existing) => {
                if existing.owner_did != owner_did {
                    return Err(MachineError::NotOwner);
                }
                MachineDeployment {
                    id: id.clone(),
                    name: name.to_string(),
                    owner_did: owner_did.to_string(),
                    version: existing.version + 1,
                    artifact_caid: artifact_caid.to_string(),
                    internal_port,
                    resources,
                    sealed_env,
                    tee_required,
                    price_per_request,
                    created_at: existing.created_at,
                    updated_at: now,
                }
            }
            None => MachineDeployment {
                id: id.clone(),
                name: name.to_string(),
                owner_did: owner_did.to_string(),
                version: 1,
                artifact_caid: artifact_caid.to_string(),
                internal_port,
                resources,
                sealed_env,
                tee_required,
                price_per_request,
                created_at: now,
                updated_at: now,
            },
        };

        self.persist(&deployment)?;
        self.machines.insert(id, deployment.clone());
        Ok(deployment)
    }

    pub fn get(&self, id: &str) -> Option<MachineDeployment> {
        self.machines.get(id).map(|d| d.clone())
    }

    pub fn list(&self, owner_did: Option<&str>) -> Vec<MachineDeployment> {
        self.machines
            .iter()
            .filter(|d| owner_did.is_none_or(|o| d.owner_did == o))
            .map(|d| d.clone())
            .collect()
    }

    /// Remove a deployment. `owner_did` must match. Returns the removed record.
    pub fn remove(&self, id: &str, owner_did: &str) -> Result<MachineDeployment, MachineError> {
        {
            let deployment = self
                .machines
                .get(id)
                .ok_or_else(|| MachineError::NotFound(id.to_string()))?;
            if deployment.owner_did != owner_did {
                return Err(MachineError::NotOwner);
            }
        }
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &machine_key(id))
                .map_err(|e| MachineError::Storage(format!("machine delete: {e}")))?;
        }
        let (_, deployment) = self
            .machines
            .remove(id)
            .ok_or_else(|| MachineError::NotFound(id.to_string()))?;
        debug!("removed machine deployment {id}");
        Ok(deployment)
    }
}

impl Default for MachineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Running state of a microVM as reported by the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MachineRunState {
    /// No microVM is running for this deployment on this node.
    Stopped,
    /// The microVM is booting; the guest server is not yet accepting connections.
    Starting,
    /// The guest server is accepting connections on `internal_port`.
    Running,
    /// The microVM exited or failed; `detail` carries the reason.
    Failed,
}

/// A status snapshot for a deployment on this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineStatus {
    pub id: String,
    pub version: u64,
    pub state: MachineRunState,
    /// Free-form detail (exit reason, boot progress). Empty when nominal.
    #[serde(default)]
    pub detail: String,
}

#[cfg(feature = "firecracker")]
pub use supervisor::MachineSupervisor;

/// Firecracker microVM supervisor. Present only under the `firecracker` feature
/// and only meaningful on a node that advertises the `machine` capability
/// (`/dev/kvm`, root / `CAP_NET_ADMIN`, jailer). Manages the microVM lifecycle
/// per deployment: fetch the image over iroh, unseal env in-enclave, launch
/// Firecracker under the jailer via its unix-socket REST API, and expose the
/// guest loopback port to the ingress bridge.
#[cfg(feature = "firecracker")]
mod supervisor {
    use super::*;
    use std::time::Duration;

    /// A launched microVM instance the supervisor tracks. The forwarding bridge
    /// dials `guest_addr` (the host-side tap address mapped to the guest
    /// loopback) for each request.
    #[derive(Debug, Clone)]
    struct RunningMachine {
        version: u64,
        state: MachineRunState,
        detail: String,
        /// Host-side socket address the ingress bridge dials to reach the guest
        /// server (the tap NIC address plus the deployment's `internal_port`).
        guest_addr: std::net::SocketAddr,
        /// Jailer instance id (`<id>-v<version>`), used to reap the chroot on stop.
        inst: String,
        /// Host tap device backing the guest NIC, torn down on stop.
        tap: String,
        /// The jailer child process. Held so the microVM lives as long as this
        /// entry; `kill_on_drop` reaps it when the entry is removed. Shared behind
        /// an `Arc` so `RunningMachine` stays cloneable.
        child: Arc<parking_lot::Mutex<Option<tokio::process::Child>>>,
    }

    /// Supervises Firecracker microVMs for machine deployments assigned to this
    /// node. One instance per node, shared behind an `Arc`.
    pub struct MachineSupervisor {
        /// iroh resolver used to fetch the content-addressed microVM image.
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        /// The node's X25519 sealing keypair. Sealed env vars are unwrapped
        /// against this at launch; it never leaves the node.
        sealing_key: Arc<tenzro_crypto::encryption::X25519KeyPair>,
        /// Firecracker binary path (defaults to `firecracker` on PATH).
        firecracker_bin: String,
        /// Jailer binary path (defaults to `jailer` on PATH).
        jailer_bin: String,
        /// Directory the jailer chroots microVMs under.
        chroot_base: std::path::PathBuf,
        /// Operator-provided uncompressed guest kernel (`vmlinux`). The kernel is
        /// node infrastructure, not per-app: every microVM on this node boots the
        /// same operator-pinned kernel, and the app blob carries only the rootfs.
        /// Defaults to `<chroot_base>/vmlinux`.
        kernel_path: std::path::PathBuf,
        /// Monotonic counter used to derive a unique tap device name and
        /// host/guest IP pair per launched microVM.
        tap_seq: std::sync::atomic::AtomicU32,
        /// Unprivileged uid the jailer drops the microVM to. The jailer sets up
        /// the chroot as root, then `setuid`s to this before exec'ing
        /// firecracker so a guest escape lands on an unprivileged host user.
        /// Defaults to [`DEFAULT_JAILER_UID`].
        jailer_uid: u32,
        /// Unprivileged gid the jailer drops the microVM to. Defaults to
        /// [`DEFAULT_JAILER_GID`].
        jailer_gid: u32,
        /// cgroup version the jailer places the microVM in for resource
        /// accounting (`2` for unified cgroup v2, `1` for legacy). Defaults to
        /// [`DEFAULT_JAILER_CGROUP_VERSION`].
        jailer_cgroup_version: u8,
        /// Seccomp filter level firecracker installs on itself (`2` = advanced
        /// per-thread filters, the firecracker default; `0` disables). Defaults
        /// to [`DEFAULT_JAILER_SECCOMP_LEVEL`].
        jailer_seccomp_level: u8,
        running: DashMap<String, RunningMachine>,
    }

    impl std::fmt::Debug for MachineSupervisor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MachineSupervisor")
                .field("running", &self.running.len())
                .field("chroot_base", &self.chroot_base)
                .finish()
        }
    }

    impl MachineSupervisor {
        pub fn new(
            resolver: Arc<dyn tenzro_iroh::IrohResolver>,
            sealing_key: Arc<tenzro_crypto::encryption::X25519KeyPair>,
            chroot_base: std::path::PathBuf,
        ) -> Self {
            let kernel_path = chroot_base.join("vmlinux");
            Self {
                resolver,
                sealing_key,
                firecracker_bin: "firecracker".into(),
                jailer_bin: "jailer".into(),
                chroot_base,
                kernel_path,
                tap_seq: std::sync::atomic::AtomicU32::new(0),
                jailer_uid: DEFAULT_JAILER_UID,
                jailer_gid: DEFAULT_JAILER_GID,
                jailer_cgroup_version: DEFAULT_JAILER_CGROUP_VERSION,
                jailer_seccomp_level: DEFAULT_JAILER_SECCOMP_LEVEL,
                running: DashMap::new(),
            }
        }

        pub fn with_binaries(mut self, firecracker_bin: String, jailer_bin: String) -> Self {
            self.firecracker_bin = firecracker_bin;
            self.jailer_bin = jailer_bin;
            self
        }

        /// Override the unprivileged uid/gid the jailer drops microVMs to. The
        /// defaults ([`DEFAULT_JAILER_UID`] / [`DEFAULT_JAILER_GID`]) run every
        /// guest as a non-root host account; pass `0` for either only on a host
        /// where an unprivileged account cannot be provisioned.
        pub fn with_jailer_identity(mut self, uid: u32, gid: u32) -> Self {
            self.jailer_uid = uid;
            self.jailer_gid = gid;
            self
        }

        /// Override the jailer cgroup version and firecracker seccomp level.
        /// `cgroup_version` is clamped to `1` or `2`; `seccomp_level` to `0..=2`.
        pub fn with_jailer_isolation(mut self, cgroup_version: u8, seccomp_level: u8) -> Self {
            self.jailer_cgroup_version = if cgroup_version == 1 { 1 } else { 2 };
            self.jailer_seccomp_level = seccomp_level.min(2);
            self
        }

        /// Override the operator-pinned guest kernel path.
        pub fn with_kernel(mut self, kernel_path: std::path::PathBuf) -> Self {
            self.kernel_path = kernel_path;
            self
        }

        /// Unseal a deployment's environment secrets in-process (the node is the
        /// enclave boundary). Returns `(name, plaintext)` pairs to pass to the
        /// guest at boot. A secret that fails to unwrap is fatal for the launch —
        /// running with a missing secret would silently misconfigure the app.
        fn unseal_env(
            &self,
            deployment: &MachineDeployment,
        ) -> Result<Vec<(String, String)>, MachineError> {
            let mut out = Vec::with_capacity(deployment.sealed_env.len());
            for var in &deployment.sealed_env {
                let envelope: tenzro_crypto::encryption::EncryptedEnvelope =
                    serde_json::from_value(var.sealed_value.clone()).map_err(|e| {
                        MachineError::Supervisor(format!("sealed env {}: decode: {e}", var.name))
                    })?;
                let plaintext =
                    tenzro_crypto::encryption::envelope_decrypt(&self.sealing_key, &envelope)
                        .map_err(|e| {
                            MachineError::Supervisor(format!(
                                "sealed env {}: unseal: {e}",
                                var.name
                            ))
                        })?;
                let value = String::from_utf8(plaintext).map_err(|e| {
                    MachineError::Supervisor(format!("sealed env {}: non-utf8: {e}", var.name))
                })?;
                out.push((var.name.clone(), value));
            }
            Ok(out)
        }

        /// Ensure a microVM is running for `deployment`, launching one if needed.
        /// Idempotent: a matching-version running instance is reused; a stale
        /// version is torn down and relaunched. Returns the host-side address the
        /// ingress bridge dials.
        pub async fn ensure_running(
            &self,
            deployment: &MachineDeployment,
        ) -> Result<std::net::SocketAddr, MachineError> {
            if let Some(existing) = self.running.get(&deployment.id)
                && existing.version == deployment.version
                && existing.state == MachineRunState::Running
            {
                return Ok(existing.guest_addr);
            }
            self.launch(deployment).await
        }

        /// Fetch the image, unseal env, and boot the microVM under the jailer via
        /// the Firecracker REST API over its unix socket.
        async fn launch(
            &self,
            deployment: &MachineDeployment,
        ) -> Result<std::net::SocketAddr, MachineError> {
            let uri = tenzro_iroh::TenzroUri::Blob {
                hash: deployment.artifact_caid.clone(),
                provider_hint: None,
            };
            let image = self
                .resolver
                .fetch_bytes(&uri)
                .await
                .map_err(|e| MachineError::Supervisor(format!("image fetch: {e}")))?;
            let env = self.unseal_env(deployment)?;

            // Boot the microVM under the jailer, configure it over the
            // Firecracker unix-socket REST API (boot-source, drives, machine
            // config, network interface with a host tap), inject `env`, and
            // InstanceStart. The guest server binds `deployment.internal_port`
            // on loopback; the tap host address plus that port is what the
            // ingress bridge dials.
            let booted = self
                .boot_firecracker(deployment, &image, &env)
                .await
                .map_err(|e| MachineError::Supervisor(format!("boot: {e}")))?;
            let guest_addr = booted.guest_addr;

            self.running.insert(
                deployment.id.clone(),
                RunningMachine {
                    version: deployment.version,
                    state: MachineRunState::Running,
                    detail: String::new(),
                    guest_addr,
                    inst: booted.inst,
                    tap: booted.tap,
                    child: booted.child,
                },
            );
            info!(
                "machine {} v{} running at {guest_addr}",
                deployment.id, deployment.version
            );
            Ok(guest_addr)
        }

        /// Configure and start one Firecracker microVM under the jailer. Uses the
        /// Firecracker REST API (`PUT /boot-source`, `/drives/rootfs`,
        /// `/machine-config`, `/network-interfaces/eth0`, `PUT /actions
        /// {InstanceStart}`) over the jailer-scoped unix socket. Returns the
        /// host-side address that reaches the guest's `internal_port`.
        async fn boot_firecracker(
            &self,
            deployment: &MachineDeployment,
            image: &[u8],
            env: &[(String, String)],
        ) -> Result<Booted, MachineError> {
            use std::sync::atomic::Ordering;

            if !std::path::Path::new("/dev/kvm").exists() {
                return Err(MachineError::Supervisor(
                    "/dev/kvm not present — node lacks the machine capability".into(),
                ));
            }
            let kernel = tokio::fs::read(&self.kernel_path).await.map_err(|e| {
                MachineError::Supervisor(format!(
                    "guest kernel {}: {e}",
                    self.kernel_path.display()
                ))
            })?;

            // Per-instance chroot. The id is filesystem-safe (hex from
            // compute_site_id); the version keeps redeploys from colliding with a
            // not-yet-reaped predecessor.
            let inst = format!("{}-v{}", deployment.id, deployment.version);
            let chroot = self.chroot_base.join(&inst);
            let root = chroot.join("root");
            tokio::fs::create_dir_all(&root)
                .await
                .map_err(|e| MachineError::Supervisor(format!("chroot {}: {e}", root.display())))?;

            // Stage kernel + rootfs into the chroot. Firecracker (under the
            // jailer) resolves paths relative to the chroot root.
            let kernel_rel = "vmlinux";
            let rootfs_rel = "rootfs.ext4";
            tokio::fs::write(root.join(kernel_rel), &kernel)
                .await
                .map_err(|e| MachineError::Supervisor(format!("stage kernel: {e}")))?;
            tokio::fs::write(root.join(rootfs_rel), image)
                .await
                .map_err(|e| MachineError::Supervisor(format!("stage rootfs: {e}")))?;

            // Deterministic /30 per instance inside 172.16.0.0/12. Each microVM
            // gets its own 4-address block (network / host / guest / broadcast);
            // the block base within the /12 is `seq * 4`, so host = base+1 and
            // guest = base+2 are a properly aligned /30 pair that can't collide
            // across sequences. The /12 holds 2^20 addresses = 2^18 blocks; the
            // sequence wraps at that bound.
            let seq = self.tap_seq.fetch_add(1, Ordering::Relaxed) & 0x3ffff;
            let net_base = (172u32 << 24) | (16u32 << 16); // 172.16.0.0/12 start
            let addr = |offset: u32| -> std::net::Ipv4Addr {
                std::net::Ipv4Addr::from(net_base + (seq << 2) + offset)
            };
            let host_ip = addr(1);
            let guest_ip = addr(2);
            let tap = format!("fc-{seq:x}");

            self.create_tap(&tap, host_ip).await?;

            // Launch firecracker under the jailer. The jailer creates the chroot,
            // drops privileges, and exposes the API socket at
            // <chroot>/root/run/firecracker.socket.
            let api_sock = root.join("run").join("firecracker.socket");
            let child = self
                .spawn_jailer(&inst, &chroot)
                .await
                .map_err(|e| MachineError::Supervisor(format!("jailer spawn: {e}")))?;
            self.wait_for_socket(&api_sock).await?;

            // Guest kernel cmdline: static IP config on eth0 + serial console off.
            let boot_args = format!(
                "console=ttyS0 reboot=k panic=1 pci=off ip={guest}::{host}:255.255.255.252::eth0:off",
                guest = guest_ip,
                host = host_ip,
            );

            self.api_put(
                &api_sock,
                "/boot-source",
                &serde_json::json!({
                    "kernel_image_path": kernel_rel,
                    "boot_args": boot_args,
                }),
            )
            .await?;
            self.api_put(
                &api_sock,
                "/drives/rootfs",
                &serde_json::json!({
                    "drive_id": "rootfs",
                    "path_on_host": rootfs_rel,
                    "is_root_device": true,
                    "is_read_only": false,
                }),
            )
            .await?;
            self.api_put(
                &api_sock,
                "/machine-config",
                &serde_json::json!({
                    "vcpu_count": deployment.resources.vcpus,
                    "mem_size_mib": deployment.resources.mem_mib,
                    "smt": false,
                }),
            )
            .await?;
            self.api_put(
                &api_sock,
                "/network-interfaces/eth0",
                &serde_json::json!({
                    "iface_id": "eth0",
                    "host_dev_name": tap,
                    "guest_mac": guest_mac(seq),
                }),
            )
            .await?;

            // Env secrets reach the guest over MMDS (the guest init reads
            // http://169.254.169.254/env at boot). MMDS is memory-only; the
            // plaintext never lands on the host filesystem.
            if !env.is_empty() {
                let env_obj: serde_json::Map<String, serde_json::Value> = env
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect();
                self.api_put(
                    &api_sock,
                    "/mmds/config",
                    &serde_json::json!({
                        "network_interfaces": ["eth0"],
                        "ipv4_address": "169.254.169.254",
                    }),
                )
                .await?;
                self.api_put(&api_sock, "/mmds", &serde_json::json!({ "env": env_obj }))
                    .await?;
            }

            self.api_put(
                &api_sock,
                "/actions",
                &serde_json::json!({ "action_type": "InstanceStart" }),
            )
            .await?;

            let guest_addr =
                std::net::SocketAddr::new(std::net::IpAddr::V4(guest_ip), deployment.internal_port);
            self.wait_for_guest(guest_addr).await?;
            Ok(Booted {
                guest_addr,
                inst,
                tap,
                child: Arc::new(parking_lot::Mutex::new(Some(child))),
            })
        }

        /// Create the host tap device and give it the /30 host address. Uses the
        /// `ip` tooling (the same path the jailer expects the operator to have
        /// pre-provisioned); requires `CAP_NET_ADMIN`.
        async fn create_tap(
            &self,
            tap: &str,
            host_ip: std::net::Ipv4Addr,
        ) -> Result<(), MachineError> {
            run_ok("ip", &["tuntap", "add", tap, "mode", "tap"]).await?;
            run_ok("ip", &["addr", "add", &format!("{host_ip}/30"), "dev", tap]).await?;
            run_ok("ip", &["link", "set", tap, "up"]).await?;
            Ok(())
        }

        /// Spawn `jailer --exec-file <firecracker> --id <inst> --chroot-base-dir
        /// <base> ...`. The jailer daemonizes firecracker into the chroot.
        ///
        /// Hardened defaults: the microVM is dropped to an unprivileged
        /// `--uid`/`--gid` (so a guest escape lands on a non-root host account),
        /// placed in a `--cgroup-version` hierarchy for resource accounting, and
        /// firecracker runs its advanced `--seccomp-level` syscall filter. All
        /// are operator-overridable via [`MachineSupervisor::with_jailer_identity`]
        /// and [`MachineSupervisor::with_jailer_isolation`].
        async fn spawn_jailer(
            &self,
            inst: &str,
            _chroot: &std::path::Path,
        ) -> Result<tokio::process::Child, std::io::Error> {
            let mut cmd = tokio::process::Command::new(&self.jailer_bin);
            cmd.arg("--id")
                .arg(inst)
                .arg("--exec-file")
                .arg(&self.firecracker_bin)
                .arg("--chroot-base-dir")
                .arg(&self.chroot_base)
                .arg("--uid")
                .arg(self.jailer_uid.to_string())
                .arg("--gid")
                .arg(self.jailer_gid.to_string())
                .arg("--cgroup-version")
                .arg(self.jailer_cgroup_version.to_string())
                .arg("--")
                .arg("--api-sock")
                .arg("run/firecracker.socket")
                .arg("--seccomp-level")
                .arg(self.jailer_seccomp_level.to_string());
            cmd.kill_on_drop(true).spawn()
        }

        /// PUT a JSON body to the Firecracker REST API over its unix socket. The
        /// API answers `204 No Content` on success; any other status is fatal for
        /// the launch. Speaks HTTP/1.1 directly — the request set is small and
        /// fixed, so no HTTP client dependency is linked.
        async fn api_put(
            &self,
            api_sock: &std::path::Path,
            path: &str,
            body: &serde_json::Value,
        ) -> Result<(), MachineError> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let payload = serde_json::to_vec(body)
                .map_err(|e| MachineError::Supervisor(format!("api encode: {e}")))?;
            let mut stream = tokio::net::UnixStream::connect(api_sock)
                .await
                .map_err(|e| MachineError::Supervisor(format!("api connect {path}: {e}")))?;
            let req = format!(
                "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
                len = payload.len(),
            );
            stream
                .write_all(req.as_bytes())
                .await
                .map_err(|e| MachineError::Supervisor(format!("api write {path}: {e}")))?;
            stream
                .write_all(&payload)
                .await
                .map_err(|e| MachineError::Supervisor(format!("api write {path}: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| MachineError::Supervisor(format!("api flush {path}: {e}")))?;

            let mut resp = Vec::with_capacity(256);
            stream
                .read_to_end(&mut resp)
                .await
                .map_err(|e| MachineError::Supervisor(format!("api read {path}: {e}")))?;
            let head = String::from_utf8_lossy(&resp);
            let status_ok = head
                .lines()
                .next()
                .map(|l| l.contains(" 204") || l.contains(" 200"))
                .unwrap_or(false);
            if !status_ok {
                let first = head.lines().next().unwrap_or("").to_string();
                return Err(MachineError::Supervisor(format!(
                    "api {path} rejected: {first}"
                )));
            }
            Ok(())
        }

        /// Wait for the jailer to create the API socket before configuring the VM.
        async fn wait_for_socket(&self, api_sock: &std::path::Path) -> Result<(), MachineError> {
            for _ in 0..200 {
                if api_sock.exists() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(MachineError::Supervisor(
                "firecracker API socket did not appear".into(),
            ))
        }

        /// Poll the guest server until it accepts a TCP connection on
        /// `internal_port`, so ingress never bridges to a not-yet-listening guest.
        async fn wait_for_guest(
            &self,
            guest_addr: std::net::SocketAddr,
        ) -> Result<(), MachineError> {
            for _ in 0..400 {
                if tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::TcpStream::connect(guest_addr),
                )
                .await
                .ok()
                .and_then(|r| r.ok())
                .is_some()
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(MachineError::Supervisor(format!(
                "guest never listened on {guest_addr}"
            )))
        }

        /// Tear down the microVM for a deployment (used on remove / redeploy).
        /// The jailer child is `kill_on_drop`, so dropping our tracked entry stops
        /// the process; here we remove the host tap and the instance chroot so a
        /// redeploy of the same id gets a clean slate.
        pub async fn stop(&self, id: &str) -> Result<(), MachineError> {
            if let Some((_, m)) = self.running.remove(id) {
                let child = m.child.lock().take();
                if let Some(mut child) = child {
                    let _ = child.kill().await;
                }
                let _ = run_ok("ip", &["link", "del", &m.tap]).await;
                let chroot = self.chroot_base.join(&m.inst);
                let _ = tokio::fs::remove_dir_all(&chroot).await;
                debug!("stopped machine {id} (tap {}, chroot {})", m.tap, m.inst);
            }
            Ok(())
        }

        /// Status snapshot for a deployment on this node.
        pub fn status(&self, deployment: &MachineDeployment) -> MachineStatus {
            match self.running.get(&deployment.id) {
                Some(m) => MachineStatus {
                    id: deployment.id.clone(),
                    version: m.version,
                    state: m.state.clone(),
                    detail: m.detail.clone(),
                },
                None => MachineStatus {
                    id: deployment.id.clone(),
                    version: deployment.version,
                    state: MachineRunState::Stopped,
                    detail: String::new(),
                },
            }
        }
    }

    /// Result of a successful `boot_firecracker`: how ingress reaches the guest
    /// plus the handles the supervisor keeps to run and later reap the microVM.
    struct Booted {
        guest_addr: std::net::SocketAddr,
        inst: String,
        tap: String,
        child: Arc<parking_lot::Mutex<Option<tokio::process::Child>>>,
    }

    /// Run a host command to completion, mapping a non-zero exit to a supervisor
    /// error with the captured stderr. Used for the `ip` tap-provisioning steps.
    async fn run_ok(program: &str, args: &[&str]) -> Result<(), MachineError> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|e| MachineError::Supervisor(format!("{program}: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MachineError::Supervisor(format!(
                "{program} {}: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Derive a locally-administered guest MAC from the launch sequence so each
    /// microVM's NIC is distinct. Sets the locally-administered bit (0x02) and
    /// clears the multicast bit.
    fn guest_mac(seq: u32) -> String {
        let b = seq.to_be_bytes();
        format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3])
    }
}
