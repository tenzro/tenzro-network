//! # tenzro-agent-kit
//!
//! Registry-driven autonomous agent runtime for Tenzro Network.
//!
//! This crate is the **glue layer** that lets a user spawn and run an
//! autonomous agent without ever touching Rust source code.
//! Every agent is a JSON template manifest published to the existing
//! `CF_AGENT_TEMPLATES` registry. At spawn time the kit:
//!
//!   1. Fetches the template by id from the registry over JSON-RPC
//!   2. Auto-discovers required tools from `CF_TOOLS` by tag query
//!   3. Auto-discovers required skills from `CF_SKILLS` by tag query
//!   4. Provisions a TDIP human controller identity + MPC wallet
//!   5. Provisions a TDIP machine identity with delegation scope
//!   6. Registers the agent with the [`tenzro_agent::AgentRuntime`]
//!   7. Walks the template's [`ExecutionSpec`] step list, gating each
//!      step by [`tenzro_identity::IdentityRegistry::enforce_operation`]
//!      and dispatching to the right Tenzro subsystem
//!      ([`tenzro_vm::MultiVmRuntime`], [`tenzro_bridge::BridgeRouter`],
//!      [`tenzro_payments`] clients, [`tenzro_vm::DamlExecutor`]).
//!
//! ## Zero hardcoding
//!
//! The crate has **zero hardcoded agent / tool / skill names**.
//! Everything is loaded from the registry at runtime. The 5 reference
//! agents bundled in `reference_templates/*.json` are auto-published to
//! the registry on first node startup via [`bootstrap`], and from then
//! on are indistinguishable from any other template that a third party
//! publishes via `tenzro_registerAgentTemplate`.
//!
//! ## Public API
//!
//! - [`AgentKit`] — top-level client; one instance per node
//! - [`SpawnArgs`] — per-spawn configuration
//! - [`SpawnedAgent`] — handle to a spawned agent
//! - [`RunOptions`] — per-run configuration
//! - [`RunReport`] — execution result
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use tenzro_agent_kit::{AgentKit, SpawnArgs, RunOptions};
//! use tenzro_identity::{IdentityRegistry, WalletBinder};
//! use tenzro_agent::AgentRuntime;
//! use tenzro_types::identity::KycTier;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let registry = Arc::new(IdentityRegistry::with_wallet_binder(Arc::new(WalletBinder::new()?)));
//! let runtime = Arc::new(AgentRuntime::new()?);
//! let kit = AgentKit::new("http://127.0.0.1:8545", registry, runtime);
//!
//! // Bootstrap the 5 reference templates (idempotent).
//! kit.bootstrap_reference_templates().await?;
//!
//! // Discover by tag instead of hardcoding an id.
//! let template = kit.discover_by_tag("yield-router").await?
//!     .into_iter()
//!     .next()
//!     .expect("yield-router template not found");
//!
//! let spawned = kit.spawn(&template.template_id, SpawnArgs {
//!     controller_display_name: "Acme AM".to_string(),
//!     kyc_tier: KycTier::Full,
//!     context: Default::default(),
//!     parent_machine_did: None,
//! }).await?;
//!
//! let report = kit.run(&spawned, RunOptions::default()).await?;
//! println!("steps executed: {}", report.steps_executed);
//! # Ok(())
//! # }
//! ```

mod auth;
mod bootstrap;
mod error;
mod executor;
mod registry;
mod resolver;
mod spawner;
mod spec;

#[cfg(feature = "wasi-skills")]
pub mod wasm;

pub use auth::{AgentAuthRequest, AgentCredentials, AuthIssuer, DpopSigner};
pub use bootstrap::{bootstrap_reference_templates, BootstrapReport};
pub use error::AgentKitError;
pub use executor::{ExecutionContext, RunOptions, RunReport, StepResult};
pub use registry::RegistryClient;
pub use resolver::{DiscoveredResources, TemplateResolver};
pub use spawner::{AgentSpawner, SpawnArgs, SpawnedAgent};

// Re-export the spec types from `tenzro-types` so consumers don't need
// a separate dependency just to construct templates.
pub use tenzro_types::agent_template::{
    AgentCapability, AgentPricingModel, AgentRuntimeRequirements, AgentTemplate,
    AgentTemplateFilter, AgentTemplateStatus, AgentTemplateType, DelegationSpec,
    ExecutionBackend, ExecutionSpec, ExecutionStep, HardCaps, SvmAccountMeta,
};

use std::sync::Arc;

use tenzro_agent::AgentRuntime;
use tenzro_identity::IdentityRegistry;

/// Top-level client for the registry-driven agent runtime.
///
/// One instance per node. Cheap to clone (all internal state is `Arc`-wrapped).
#[derive(Clone)]
pub struct AgentKit {
    rpc_url: Arc<String>,
    identity_registry: Arc<IdentityRegistry>,
    agent_runtime: Arc<AgentRuntime>,
    registry: Arc<RegistryClient>,
    /// Optional auth issuer. When set, `spawn()` returns a `SpawnedAgent`
    /// whose `credentials` field carries a DPoP-bound JWT + signer; the
    /// executor's authenticated dispatch paths (EVM/SVM/DAML) use these
    /// credentials to call `tenzro_signAndSendTransaction` /
    /// `tenzro_svmDispatch` / DAML submission RPCs on the agent's behalf.
    auth_issuer: Option<Arc<dyn AuthIssuer>>,
}

impl AgentKit {
    /// Constructs a new `AgentKit` pointing at the local node's JSON-RPC
    /// endpoint, sharing the node's [`IdentityRegistry`] and [`AgentRuntime`].
    ///
    /// No [`AuthIssuer`] is wired. Any spawned agent's authenticated
    /// dispatch steps (EvmDispatch / SvmDispatch / DamlSubmit) will fail
    /// loudly with a "lacks DPoP credentials" error. Use
    /// [`AgentKit::with_auth_issuer`] to enable the full path.
    pub fn new(
        rpc_url: impl Into<String>,
        identity_registry: Arc<IdentityRegistry>,
        agent_runtime: Arc<AgentRuntime>,
    ) -> Self {
        let rpc_url = Arc::new(rpc_url.into());
        let registry = Arc::new(RegistryClient::new((*rpc_url).clone()));
        Self {
            rpc_url,
            identity_registry,
            agent_runtime,
            registry,
            auth_issuer: None,
        }
    }

    /// Constructs a new `AgentKit` with a DPoP-capable [`AuthIssuer`] wired.
    /// Every `spawn()` call will mint per-agent DPoP-bound JWT credentials
    /// scoped to the template's `DelegationSpec`.
    pub fn with_auth_issuer(
        rpc_url: impl Into<String>,
        identity_registry: Arc<IdentityRegistry>,
        agent_runtime: Arc<AgentRuntime>,
        auth_issuer: Arc<dyn AuthIssuer>,
    ) -> Self {
        let rpc_url = Arc::new(rpc_url.into());
        let registry = Arc::new(RegistryClient::new((*rpc_url).clone()));
        Self {
            rpc_url,
            identity_registry,
            agent_runtime,
            registry,
            auth_issuer: Some(auth_issuer),
        }
    }

    /// Returns the configured RPC endpoint.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Returns a handle to the inner [`RegistryClient`] for advanced callers.
    pub fn registry(&self) -> &Arc<RegistryClient> {
        &self.registry
    }

    /// Returns a handle to the inner [`IdentityRegistry`].
    pub fn identity_registry(&self) -> &Arc<IdentityRegistry> {
        &self.identity_registry
    }

    /// Returns a handle to the inner [`AgentRuntime`].
    pub fn agent_runtime(&self) -> &Arc<AgentRuntime> {
        &self.agent_runtime
    }

    /// Lists all available templates in the registry, optionally filtered.
    pub async fn list_templates(
        &self,
        filter: Option<AgentTemplateFilter>,
    ) -> Result<Vec<AgentTemplate>, AgentKitError> {
        self.registry.list_templates(filter).await
    }

    /// Fetches a single template by id from the registry.
    pub async fn get_template(&self, template_id: &str) -> Result<AgentTemplate, AgentKitError> {
        self.registry.get_template(template_id).await
    }

    /// Auto-discovers templates by tag. Returns every template whose
    /// `tags` vector contains the supplied tag.
    pub async fn discover_by_tag(&self, tag: &str) -> Result<Vec<AgentTemplate>, AgentKitError> {
        let all = self.registry.list_templates(None).await?;
        Ok(all
            .into_iter()
            .filter(|t| t.tags.iter().any(|x| x == tag))
            .collect())
    }

    /// Provisions identity + wallet + delegation scope and registers
    /// the agent with the [`AgentRuntime`]. All required tools and skills
    /// are auto-discovered from the template's `execution_spec.required_*_tags`.
    pub async fn spawn(
        &self,
        template_id: &str,
        args: SpawnArgs,
    ) -> Result<SpawnedAgent, AgentKitError> {
        let spawner = if let Some(issuer) = self.auth_issuer.clone() {
            AgentSpawner::with_auth_issuer(
                self.registry.clone(),
                self.identity_registry.clone(),
                self.agent_runtime.clone(),
                issuer,
            )
        } else {
            AgentSpawner::new(
                self.registry.clone(),
                self.identity_registry.clone(),
                self.agent_runtime.clone(),
            )
        };
        spawner.spawn(template_id, args).await
    }

    /// Runs the spawned agent's [`ExecutionSpec`] for at most
    /// `run_opts.max_iterations` iterations.
    pub async fn run(
        &self,
        spawned: &SpawnedAgent,
        run_opts: RunOptions,
    ) -> Result<RunReport, AgentKitError> {
        let mut executor = executor::Executor::new(
            self.registry.clone(),
            self.identity_registry.clone(),
        );
        executor.run(spawned, run_opts).await
    }

    /// Loads the bundled reference template manifests from
    /// `reference_templates/*.json` and publishes them to the registry
    /// idempotently (skips templates whose `name` + `version` already exist).
    pub async fn bootstrap_reference_templates(&self) -> Result<BootstrapReport, AgentKitError> {
        bootstrap::bootstrap_reference_templates(&self.registry).await
    }
}
