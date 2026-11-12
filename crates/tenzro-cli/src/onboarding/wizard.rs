//! The decisions of the `tenzro setup` wizard, as pure functions.
//!
//! The wizard is one sequence: name, authority, role, funding, reachability,
//! access, service. Everything that can be decided without a terminal lives
//! here so it can be tested: which authorities a machine may offer, how the
//! operation mode maps onto the evidence the network accepts, which roles a
//! machine meets the requirements of, whether a wallet needs funding, and
//! where a half-finished setup resumes.
//!
//! Roles follow requirements, not hardware. Nothing here looks at the device
//! class, the operating system or the CPU architecture: a Pi, a Jetson, a Mac,
//! a PC and a server are all eligible for a role exactly when they meet the
//! role's stated requirements ([`MachineFacts`] carries measurements only).

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tenzro_types::network::{NetworkRole, RoleSet};

use super::role::JoinRole;
use crate::commands::hardware::HardwareProfile;

// ---------------------------------------------------------------------------
// Steps and resume
// ---------------------------------------------------------------------------

/// One step of the wizard, in the order it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Display name and machine name.
    Name,
    /// Who holds the identity and wallet key, and how the node is operated.
    Authority,
    /// What the user wants to be on the network.
    Role,
    /// Funding the wallet when the role needs a stake or bond.
    Funding,
    /// Public or local-only reachability.
    Reachability,
    /// Access models for providers.
    Access,
    /// Service install, start and sync.
    Service,
}

/// Every step, in order.
pub const STEPS: [Step; 7] = [
    Step::Name,
    Step::Authority,
    Step::Role,
    Step::Funding,
    Step::Reachability,
    Step::Access,
    Step::Service,
];

impl Step {
    /// The name stored in the resume record.
    pub fn slug(self) -> &'static str {
        match self {
            Step::Name => "name",
            Step::Authority => "authority",
            Step::Role => "role",
            Step::Funding => "funding",
            Step::Reachability => "reachability",
            Step::Access => "access",
            Step::Service => "service",
        }
    }

    /// The name shown to the user.
    pub fn label(self) -> &'static str {
        match self {
            Step::Name => "Name",
            Step::Authority => "Authority",
            Step::Role => "Role",
            Step::Funding => "Funding",
            Step::Reachability => "Reachability",
            Step::Access => "Access",
            Step::Service => "Service",
        }
    }

    /// The step a saved slug names.
    pub fn parse(s: &str) -> Option<Step> {
        STEPS.iter().copied().find(|st| st.slug() == s)
    }

    /// Position in the sequence, from 1.
    pub fn number(self) -> usize {
        STEPS.iter().position(|s| *s == self).unwrap_or(0) + 1
    }

    /// The step after this one, `None` after the last.
    pub fn next(self) -> Option<Step> {
        STEPS.get(self.number()).copied()
    }

    /// The progress line printed as the step starts, e.g. `Step 3 of 7: Role`.
    pub fn progress_line(self) -> String {
        format!(
            "Step {} of {}: {}",
            self.number(),
            STEPS.len(),
            self.label()
        )
    }
}

/// What a half-finished setup keeps so `tenzro setup` resumes at the step it
/// stopped at. It holds choices and public identifiers only: never a key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardRecord {
    /// The slug of the next step to run.
    pub next: String,
    /// Display name chosen at the name step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Machine name chosen at the name step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
    /// The [`Authority`] slug chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// The [`OperationMode`] slug chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Who delegates, for the agentic mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegator: Option<String>,
    /// The canonical role set chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<String>,
    /// The wallet the funding step watches, `0x` and 64 hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_account: Option<String>,
    /// The amount the funding step waits for, in wei, as decimal text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_required_wei: Option<String>,
}

impl WizardRecord {
    /// The step to resume at. An unreadable record starts over at the first
    /// step rather than guessing.
    pub fn resume_step(&self) -> Step {
        Step::parse(&self.next).unwrap_or(Step::Name)
    }

    /// Mark `done` complete: the record now points at the step after it.
    /// Returns `false` when `done` was the last step (the setup is finished).
    pub fn complete(&mut self, done: Step) -> bool {
        match done.next() {
            Some(n) => {
                self.next = n.slug().to_string();
                true
            }
            None => false,
        }
    }

    /// Whether a step has already been completed in this record.
    pub fn is_done(&self, step: Step) -> bool {
        self.resume_step().number() > step.number()
    }
}

// ---------------------------------------------------------------------------
// Authority and operation mode
// ---------------------------------------------------------------------------

/// Who holds the key behind the identity and wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// A person, in a passkey (browser or phone ceremony).
    Passkey,
    /// This machine, in its TPM 2.0 or Secure Enclave.
    MachineKey,
    /// Another machine on the network that has a TPM, for a machine without
    /// one (Pi class).
    Delegated,
}

/// What the machine can offer as authorities.
#[derive(Debug, Clone, Default)]
pub struct AuthorityFacts {
    /// A usable TPM 2.0 or Secure Enclave is present.
    pub machine_key_available: bool,
    /// Why not, when it is not. Shown instead of silently hiding the option.
    pub machine_key_reason: String,
    /// A TPM machine on the network that can hold this machine's key.
    pub delegate_machine: Option<String>,
}

impl Authority {
    /// The stored name.
    pub fn slug(self) -> &'static str {
        match self {
            Authority::Passkey => "passkey",
            Authority::MachineKey => "machine-key",
            Authority::Delegated => "delegated",
        }
    }

    /// The authority a stored name selects.
    pub fn parse(s: &str) -> Option<Authority> {
        [
            Authority::Passkey,
            Authority::MachineKey,
            Authority::Delegated,
        ]
        .into_iter()
        .find(|a| a.slug() == s)
    }

    /// One line on what the choice is.
    pub fn explain(self, facts: &AuthorityFacts) -> String {
        match self {
            Authority::Passkey => "Passkey: a person holds the key, created in your browser or on your phone.".into(),
            Authority::MachineKey => "TPM / Secure Enclave: this machine holds the key in its chip and answers for itself.".into(),
            Authority::Delegated => format!(
                "Delegated: the key lives in the TPM of {}, this machine acts through it.",
                facts.delegate_machine.as_deref().unwrap_or("another machine")
            ),
        }
    }

    /// One plain line on what losing the device or passkey means.
    pub fn loss_line(self) -> &'static str {
        match self {
            Authority::Passkey => {
                "If you lose the passkey you lose the wallet; keep it synced or add a second passkey."
            }
            Authority::MachineKey => {
                "The key never leaves the chip: if this machine is lost or wiped its identity and wallet are gone, unless you attach a passkey as recovery."
            }
            Authority::Delegated => {
                "If the holding machine is lost this machine loses its identity until you set a new authority."
            }
        }
    }
}

/// The authorities to offer. The passkey is always offered. The chip option is
/// offered only when a usable TPM or Secure Enclave exists, and the delegated
/// option only when there is no usable chip and a TPM machine on the network
/// can be named.
pub fn authority_options(f: &AuthorityFacts) -> Vec<Authority> {
    let mut v = vec![Authority::Passkey];
    if f.machine_key_available {
        v.push(Authority::MachineKey);
    } else if f.delegate_machine.is_some() {
        v.push(Authority::Delegated);
    }
    v
}

/// How the node is operated day to day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    /// A person approves actions with their passkey (`--operator self`).
    Human,
    /// The machine answers for itself from its chip (`--operator autonomous`).
    Autonomous,
    /// An AI agent operates the node under a delegation from a human passkey
    /// (`--operator agentic`).
    Agentic,
}

/// What the network accepts as proof of an operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// A WebAuthn assertion by the human's passkey.
    PasskeyAssertion,
    /// A TPM quote or Secure Enclave attestation.
    HardwareQuote,
    /// A delegation credential signed by the human's passkey.
    DelegationCredential,
}

impl Evidence {
    /// The stored name.
    pub fn slug(self) -> &'static str {
        match self {
            Evidence::PasskeyAssertion => "passkey_assertion",
            Evidence::HardwareQuote => "hardware_quote",
            Evidence::DelegationCredential => "delegation_credential",
        }
    }
}

impl OperationMode {
    /// The stored name (also the `operator_mode` of the CLI config).
    pub fn slug(self) -> &'static str {
        match self {
            OperationMode::Human => "self",
            OperationMode::Autonomous => "autonomous",
            OperationMode::Agentic => "agentic",
        }
    }

    /// The mode a `--operator` value or stored name selects.
    pub fn parse(s: &str) -> Option<OperationMode> {
        match s {
            "self" | "human" => Some(OperationMode::Human),
            "autonomous" => Some(OperationMode::Autonomous),
            "agentic" => Some(OperationMode::Agentic),
            _ => None,
        }
    }

    /// One line on what the mode is.
    pub fn explain(self) -> &'static str {
        match self {
            OperationMode::Human => {
                "Human in the loop: a person approves actions with their passkey."
            }
            OperationMode::Autonomous => {
                "Autonomous machine: the machine answers for itself from its TPM or Secure Enclave."
            }
            OperationMode::Agentic => {
                "Agentic: an AI agent operates the node under a delegation from a human passkey, with scopes, a spending limit and an expiry. The agent never holds a root key."
            }
        }
    }

    /// The only evidence that proves this mode. The network trusts this and
    /// nothing else: a label alone has no effect on permissions.
    pub fn required_evidence(self) -> Evidence {
        match self {
            OperationMode::Human => Evidence::PasskeyAssertion,
            OperationMode::Autonomous => Evidence::HardwareQuote,
            OperationMode::Agentic => Evidence::DelegationCredential,
        }
    }
}

/// The modes an authority can run under. A passkey authority can be operated
/// by a person or delegated to an agent; a chip authority answers for itself.
/// An agent is always delegated by a human passkey, never by a chip.
pub fn mode_options(authority: Authority) -> Vec<OperationMode> {
    match authority {
        Authority::Passkey => vec![OperationMode::Human, OperationMode::Agentic],
        Authority::MachineKey | Authority::Delegated => vec![OperationMode::Autonomous],
    }
}

/// A claim of an operation mode was not backed by evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// A label with no evidence at all.
    LabelOnly(OperationMode),
    /// Evidence was presented but not the kind this mode needs.
    WrongEvidence(OperationMode),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (mode, what) = match self {
            ClaimError::LabelOnly(m) => (*m, "was declared as a label with no evidence"),
            ClaimError::WrongEvidence(m) => (*m, "was backed by evidence of a different kind"),
        };
        write!(
            f,
            "The {} operation mode {what}. The network only trusts evidence it can verify, \
             so the label grants no permissions. Present {} (re-run `tenzro setup --operator {}`).",
            mode.slug(),
            mode.required_evidence().slug(),
            mode.slug()
        )
    }
}

impl std::error::Error for ClaimError {}

/// Accept a claimed mode only when the evidence it needs is presented.
pub fn verify_claim(
    claimed: OperationMode,
    presented: &[Evidence],
) -> Result<Evidence, ClaimError> {
    let need = claimed.required_evidence();
    if presented.contains(&need) {
        Ok(need)
    } else if presented.is_empty() {
        Err(ClaimError::LabelOnly(claimed))
    } else {
        Err(ClaimError::WrongEvidence(claimed))
    }
}

/// The identity record's structured mode field: the mode and the evidence
/// kind that proves it. The same value goes in the node's agent card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeRecord {
    /// The operation mode.
    pub mode: OperationMode,
    /// The evidence a verifier must check for it.
    pub evidence: Evidence,
    /// Who delegates, for the agentic mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegator: Option<String>,
}

/// URI of the agent card extension that carries the mode.
pub const AGENT_CARD_MODE_EXTENSION: &str = "https://tenzro.com/a2a/ext/operation-mode/v1";

impl ModeRecord {
    /// The record for a mode.
    pub fn new(mode: OperationMode, delegator: Option<String>) -> Self {
        Self {
            mode,
            evidence: mode.required_evidence(),
            delegator,
        }
    }

    /// The A2A agent card extension entry for this record.
    pub fn agent_card_extension(&self) -> serde_json::Value {
        serde_json::json!({
            "uri": AGENT_CARD_MODE_EXTENSION,
            "description": "How this node is operated and the evidence that proves it.",
            "required": false,
            "params": self,
        })
    }
}

/// The agentic mode's delegation terms. Narrow on purpose: who delegates, what
/// the agent may do, how much it may spend and for how long. It converts to the
/// identity crate's [`tenzro_identity::DelegationScope`], which the node
/// enforces; the delegator's passkey signs it through
/// `tenzro agent-delegation challenge delegate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDelegation {
    /// The human who delegates: a `did:tenzro:human:` identity or a `0x` account.
    pub delegator: String,
    /// Operations the agent may perform.
    pub scopes: Vec<String>,
    /// Most the agent may spend in one transaction, in wei.
    pub max_transaction_wei: u128,
    /// Most the agent may spend in a day, in wei.
    pub max_daily_wei: u128,
    /// Hours until the delegation expires.
    pub expires_in_hours: u32,
}

/// The longest delegation the wizard creates, in hours (30 days).
pub const MAX_DELEGATION_HOURS: u32 = 24 * 30;

impl AgentDelegation {
    /// Refuse terms that would delegate nothing or everything. Each message
    /// says what is wrong and how to fix it.
    pub fn validate(&self) -> Result<()> {
        let d = self.delegator.trim();
        let is_account =
            d.len() == 66 && d.starts_with("0x") && d[2..].bytes().all(|b| b.is_ascii_hexdigit());
        if d.is_empty() {
            bail!(
                "The agentic mode needs a delegator: the human whose passkey authorizes the agent. Pass --delegator <did:tenzro:human:... or 0x account>."
            );
        }
        if !is_account && !d.starts_with("did:tenzro:human:") {
            bail!(
                "The delegator `{d}` is not a human identity: an agent can only be delegated by a human passkey. Pass --delegator <did:tenzro:human:... or a 0x account of 64 hex digits>."
            );
        }
        if self.scopes.is_empty()
            || self
                .scopes
                .iter()
                .any(|s| s.trim().is_empty() || s.trim() == "*")
        {
            bail!(
                "The delegation needs named scopes and `*` is not one: list what the agent may do. Pass --delegation-scopes inference,transfer."
            );
        }
        if self.max_transaction_wei == 0 || self.max_daily_wei == 0 {
            bail!(
                "The delegation needs a spending limit above zero, or the agent could do nothing; an unlimited one is refused. Pass --delegation-limit <TNZO>."
            );
        }
        if self.max_transaction_wei > self.max_daily_wei {
            bail!(
                "The per-transaction limit is above the daily limit, which the daily limit would never allow. Lower the per-transaction limit or raise --delegation-limit."
            );
        }
        if self.expires_in_hours == 0 || self.expires_in_hours > MAX_DELEGATION_HOURS {
            bail!(
                "The delegation expiry must be between 1 and {MAX_DELEGATION_HOURS} hours. Pass --delegation-hours <hours>."
            );
        }
        Ok(())
    }

    /// The scope the node enforces, built on the identity crate's type.
    pub fn to_scope(&self) -> tenzro_identity::DelegationScope {
        let mut scope = tenzro_identity::DelegationScope::expiring_after(chrono::Duration::hours(
            i64::from(self.expires_in_hours),
        ));
        scope.allowed_operations = self.scopes.iter().map(|s| s.trim().to_string()).collect();
        scope.max_transaction_value = Some(self.max_transaction_wei);
        scope.max_daily_spend = Some(self.max_daily_wei);
        scope
    }
}

/// The authority and operation mode a setup runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// Who holds the key.
    pub authority: Authority,
    /// How the node is operated.
    pub mode: OperationMode,
}

/// Resolve the authority and mode. `flag` is `--operator`; when it is present
/// `ask` is never called. `ask(question, options)` returns the index chosen,
/// where each option is a line explaining that choice.
pub fn resolve_choice(
    flag: Option<&str>,
    facts: &AuthorityFacts,
    ask: &mut dyn FnMut(&str, &[String]) -> Result<usize>,
) -> Result<Choice> {
    if let Some(f) = flag {
        let mode = OperationMode::parse(f)
            .ok_or_else(|| anyhow!("--operator `{f}` is not one of self, autonomous, agentic"))?;
        return match mode {
            OperationMode::Human | OperationMode::Agentic => Ok(Choice {
                authority: Authority::Passkey,
                mode,
            }),
            OperationMode::Autonomous if facts.machine_key_available => Ok(Choice {
                authority: Authority::MachineKey,
                mode,
            }),
            OperationMode::Autonomous if facts.delegate_machine.is_some() => Ok(Choice {
                authority: Authority::Delegated,
                mode,
            }),
            OperationMode::Autonomous => Err(anyhow!(
                "--operator autonomous is not available on this machine: {}. \
                 Fix: use a machine with a TPM 2.0 or Secure Enclave, or use --operator self for a passkey.",
                facts.machine_key_reason
            )),
        };
    }

    let options = authority_options(facts);
    let authority = if options.len() == 1 {
        options[0]
    } else {
        let lines: Vec<String> = options
            .iter()
            .map(|a| format!("{} {}", a.explain(facts), a.loss_line()))
            .collect();
        let i = ask("Who holds the key to your identity and wallet?", &lines)?;
        *options.get(i).ok_or_else(|| anyhow!("no such authority"))?
    };
    let modes = mode_options(authority);
    let mode = if modes.len() == 1 {
        modes[0]
    } else {
        let lines: Vec<String> = modes.iter().map(|m| m.explain().to_string()).collect();
        let i = ask("How is this node operated?", &lines)?;
        *modes.get(i).ok_or_else(|| anyhow!("no such mode"))?
    };
    Ok(Choice { authority, mode })
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// What the user wants to be on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persona {
    /// Consume the network; no serving duties, no stake.
    Participant,
    /// Provide AI, storage, compute or other services, with a bond.
    Operator,
    /// Take part in consensus; always on, bond required.
    Validator,
    /// Serve public RPC; needs the chain bond of the rpc role.
    RpcProvider,
}

/// Every persona, in the order the wizard lists them.
pub const PERSONAS: [Persona; 4] = [
    Persona::Participant,
    Persona::Operator,
    Persona::Validator,
    Persona::RpcProvider,
];

/// The services an operator can provide.
pub const OPERATOR_SERVICES: [NetworkRole; 3] = [
    NetworkRole::ModelProvider,
    NetworkRole::ComputeProvider,
    NetworkRole::StorageProvider,
];

impl Persona {
    /// The name the wizard shows.
    pub fn label(self) -> &'static str {
        match self {
            Persona::Participant => "Participant",
            Persona::Operator => "Operator",
            Persona::Validator => "Validator",
            Persona::RpcProvider => "RPC provider",
        }
    }

    /// The `--mode` value this persona corresponds to, where one exists.
    pub fn mode_flag(self) -> Option<&'static str> {
        match self {
            Persona::Participant => Some("consume"),
            Persona::Operator => Some("provide"),
            Persona::Validator => Some("validate"),
            Persona::RpcProvider => None,
        }
    }

    /// The persona a `--mode` value selects.
    pub fn from_mode_flag(mode: &str) -> Option<Persona> {
        PERSONAS.into_iter().find(|p| p.mode_flag() == Some(mode))
    }

    /// The roles this persona maps onto. An operator with no service named
    /// serves AI, the `--mode provide` default.
    pub fn roles(self, services: &[NetworkRole]) -> RoleSet {
        match self {
            Persona::Participant => RoleSet::client(),
            Persona::Operator if services.is_empty() => RoleSet::from(NetworkRole::ModelProvider),
            Persona::Operator => RoleSet::from_roles(services.iter().copied()),
            Persona::Validator => RoleSet::from(NetworkRole::Validator),
            Persona::RpcProvider => RoleSet::from(NetworkRole::Rpc),
        }
    }

    /// The persona that best describes a role set given with `--roles`.
    pub fn of_roles(roles: &RoleSet) -> Persona {
        if roles.has(NetworkRole::Validator) {
            Persona::Validator
        } else if roles.has(NetworkRole::Rpc) {
            Persona::RpcProvider
        } else if roles.is_provider() {
            Persona::Operator
        } else {
            Persona::Participant
        }
    }
}

/// What a role asks of a machine. Measurements and duties only: never a device
/// class, an operating system or an architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The role, as the user knows it.
    pub role: &'static str,
    /// Memory needed, in whole GB.
    pub min_ram_gb: u32,
    /// Free storage needed, in whole GB.
    pub min_storage_gb: u32,
    /// An accelerator or unified memory is needed.
    pub accelerator: bool,
    /// A TPM 2.0 or Secure Enclave holds the role's signing keys.
    pub hardware_key: bool,
    /// The node must stay up; setup installs the service for it.
    pub always_on: bool,
    /// The stake or bond, in wei, from the protocol constants.
    pub stake_wei: u128,
}

/// The requirements of one role, `None` for a role that asks nothing.
pub fn requirement_of(role: NetworkRole) -> Option<Requirement> {
    let stake = join_role_of(role).map_or(0, |r| r.stake_minimum_wei());
    let (name, ram, disk, accel, key) = match role {
        NetworkRole::Validator => ("validator", 8, 100, false, true),
        NetworkRole::Rpc => ("RPC provider", 8, 50, false, false),
        NetworkRole::ModelProvider => ("AI provider", 8, 20, true, false),
        NetworkRole::ComputeProvider => ("compute provider", 8, 20, true, false),
        NetworkRole::StorageProvider => ("storage provider", 2, 100, false, false),
        NetworkRole::TeeProvider => ("TEE provider", 8, 20, false, false),
        _ => return None,
    };
    Some(Requirement {
        role: name,
        min_ram_gb: ram,
        min_storage_gb: disk,
        accelerator: accel,
        hardware_key: key,
        always_on: true,
        stake_wei: stake,
    })
}

/// The application role that bonds for a network role, where there is one.
pub fn join_role_of(role: NetworkRole) -> Option<JoinRole> {
    Some(match role {
        NetworkRole::Validator => JoinRole::Validator,
        NetworkRole::Rpc => JoinRole::RpcOperator,
        NetworkRole::ModelProvider => JoinRole::ModelProvider,
        NetworkRole::ComputeProvider => JoinRole::ComputeProvider,
        NetworkRole::StorageProvider => JoinRole::StorageProvider,
        NetworkRole::TeeProvider => JoinRole::TeeProvider,
        _ => return None,
    })
}

/// What the machine measures at. Built from the hardware check.
#[derive(Debug, Clone, PartialEq)]
pub struct MachineFacts {
    /// Memory, in GB (unified memory counts).
    pub ram_gb: f64,
    /// Free storage, in GB.
    pub storage_gb: f64,
    /// An accelerator or unified memory is present.
    pub accelerator: bool,
    /// A usable TPM 2.0 or Secure Enclave is present.
    pub hardware_key: bool,
}

impl MachineFacts {
    /// The measurements of a hardware profile; `hardware_key` is the result of
    /// the existing TPM / Secure Enclave check.
    pub fn from_profile(hw: &HardwareProfile, hardware_key: bool) -> Self {
        Self {
            ram_gb: hw.total_ram_gb,
            storage_gb: hw.storage_available_gb,
            accelerator: !hw.gpus.is_empty() || !hw.accelerators.is_empty() || hw.unified_memory,
            hardware_key,
        }
    }
}

/// A requirement the machine does not meet, with the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmet {
    /// What is missing and by how much.
    pub what: String,
    /// How to fix it.
    pub fix: String,
}

/// The requirements of `req` that `m` does not meet.
pub fn unmet(req: &Requirement, m: &MachineFacts) -> Vec<Unmet> {
    let mut v = Vec::new();
    if m.ram_gb + 0.5 < f64::from(req.min_ram_gb) {
        v.push(Unmet {
            what: format!(
                "{} needs {} GB of memory, this machine has {:.0} GB",
                req.role, req.min_ram_gb, m.ram_gb
            ),
            fix: "use a machine with more memory, or pick a role that needs less".into(),
        });
    }
    if m.storage_gb < f64::from(req.min_storage_gb) {
        v.push(Unmet {
            what: format!(
                "{} needs {} GB of free storage, this machine has {:.0} GB",
                req.role, req.min_storage_gb, m.storage_gb
            ),
            fix: "free disk space or point the data directory at a larger disk".into(),
        });
    }
    if req.accelerator && !m.accelerator {
        v.push(Unmet {
            what: format!(
                "{} needs an accelerator (GPU or unified memory), none was detected",
                req.role
            ),
            fix: "use a machine with a GPU, or provide storage or RPC instead".into(),
        });
    }
    if req.hardware_key && !m.hardware_key {
        v.push(Unmet {
            what: format!(
                "{} keeps its signing keys in a TPM 2.0 or Secure Enclave, none is usable",
                req.role
            ),
            fix: "enable the TPM in firmware and install tpm2-tools, or use a machine that has one"
                .into(),
        });
    }
    v
}

/// One line on what a persona requires, for the menu.
pub fn requirement_line(p: Persona, services: &[NetworkRole]) -> String {
    match p {
        Persona::Participant => "needs nothing: no stake, no always-on duty".into(),
        _ => {
            let roles = p.roles(services);
            let reqs: Vec<Requirement> = roles.iter().filter_map(requirement_of).collect();
            let ram = reqs.iter().map(|r| r.min_ram_gb).max().unwrap_or(0);
            let disk = reqs.iter().map(|r| r.min_storage_gb).max().unwrap_or(0);
            let stake: u128 = reqs.iter().map(|r| r.stake_wei).sum();
            let mut parts = vec![
                format!("{ram} GB memory"),
                format!("{disk} GB free storage"),
            ];
            if reqs.iter().any(|r| r.accelerator) {
                parts.push("an accelerator for AI and compute".into());
            }
            if reqs.iter().any(|r| r.hardware_key) {
                parts.push("a TPM or Secure Enclave".into());
            }
            if reqs.iter().any(|r| r.always_on) {
                parts.push("always on".into());
            }
            parts.push(format!(
                "a bond of {} TNZO",
                stake / tenzro_types::constants::ONE_TNZO
            ));
            format!("needs {}", parts.join(", "))
        }
    }
}

/// Whether a persona can be chosen on this machine, and what is unmet if not.
pub fn persona_gate(
    p: Persona,
    services: &[NetworkRole],
    m: &MachineFacts,
) -> Result<(), Vec<Unmet>> {
    unmet_for(&p.roles(services), m)
}

fn unmet_for(roles: &RoleSet, m: &MachineFacts) -> Result<(), Vec<Unmet>> {
    let all: Vec<Unmet> = roles
        .iter()
        .filter_map(requirement_of)
        .flat_map(|r| unmet(&r, m))
        .collect();
    if all.is_empty() { Ok(()) } else { Err(all) }
}

/// Whether a persona is offered on this machine. An operator is offered when
/// at least one service fits; the unmet list then comes from the service that
/// came closest, so the user sees the shortest way in.
pub fn persona_availability(p: Persona, m: &MachineFacts) -> Result<(), Vec<Unmet>> {
    if p != Persona::Operator {
        return persona_gate(p, &[], m);
    }
    let mut best: Option<Vec<Unmet>> = None;
    for svc in OPERATOR_SERVICES {
        match persona_gate(p, &[svc], m) {
            Ok(()) => return Ok(()),
            Err(u) if best.as_ref().is_none_or(|b| u.len() < b.len()) => best = Some(u),
            Err(_) => {}
        }
    }
    Err(best.unwrap_or_default())
}

/// The gate for roles given with `--roles` or `--mode`: the same checks, as an
/// error that says what is unmet and how to fix it.
pub fn gate_roles(roles: &RoleSet, m: &MachineFacts) -> Result<()> {
    match unmet_for(roles, m) {
        Ok(()) => Ok(()),
        Err(all) => {
            let lines: Vec<String> = all
                .iter()
                .map(|u| format!("  - {}. Fix: {}.", u.what, u.fix))
                .collect();
            Err(anyhow!(
                "This machine does not meet the requirements of the chosen roles:\n{}\nPick other roles or fix the above and run `tenzro setup` again.",
                lines.join("\n")
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Validator admission
// ---------------------------------------------------------------------------

/// What the network reports about who may become a validator, read before the
/// role is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Any machine that meets the validator requirements may bond.
    Open,
    /// Only admitted accounts may; `admitted` says whether this machine's is.
    Closed {
        /// Whether this machine's account is on the admitted set.
        admitted: bool,
    },
    /// The network could not be asked. Nothing is refused here; the chain
    /// refuses a registration that is not admitted either way.
    Unknown,
}

impl Admission {
    /// Reads the reply of `tenzro_getNetworkParams` with
    /// `{ "validator_admission": true, "address": ... }`.
    pub fn from_reply(v: &serde_json::Value) -> Admission {
        match v.get("mode").and_then(serde_json::Value::as_str) {
            Some("open") => Admission::Open,
            Some("closed") => Admission::Closed {
                admitted: v
                    .get("admitted")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            },
            _ => Admission::Unknown,
        }
    }

    /// Whether the validator role is refused to this machine.
    pub fn refuses_validator(&self) -> bool {
        matches!(self, Admission::Closed { admitted: false })
    }
}

/// What the refusal says, in plain words: what happened, why, and what to do.
pub fn admission_refusal() -> String {
    "Validator admission is closed while the network stabilises, and this machine is not on the admitted set.\n\
     Why: the first validators are the founding set; new validators are admitted by a governance vote once the network is stable.\n\
     Fix: run as an operator or a participant now. To ask to be admitted as a validator, write to team@tenzro.com."
        .to_string()
}

/// The menu note on the validator line while admission is closed to this machine.
pub fn admission_menu_note(p: Persona, a: &Admission) -> Option<String> {
    (p == Persona::Validator && a.refuses_validator()).then(|| {
        " [closed while the network stabilises: run as an operator or participant]".to_string()
    })
}

/// The gate for roles given with `--roles` or `--mode`: a validator role is
/// refused with [`admission_refusal`] while admission is closed to this machine.
pub fn gate_admission(roles: &RoleSet, a: &Admission) -> Result<()> {
    if roles.is_validator() && a.refuses_validator() {
        return Err(anyhow!(
            "{}\nPick the operator or participant role and run `tenzro setup` again.",
            admission_refusal()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Funding
// ---------------------------------------------------------------------------

/// Whether the wallet must be funded before the setup can go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Funding {
    /// The role needs no stake.
    NotNeeded,
    /// The wallet already holds the amount.
    Met,
    /// The wallet holds less than the amount.
    Short {
        /// Amount needed, in wei.
        required_wei: u128,
        /// Amount still missing, in wei.
        shortfall_wei: u128,
        /// The balance could not be read, so the shortfall is the full amount.
        balance_unknown: bool,
    },
}

/// The funding decision. An unreadable balance counts as zero, and says so.
pub fn funding_decision(required_wei: u128, balance_wei: Option<u128>) -> Funding {
    if required_wei == 0 {
        return Funding::NotNeeded;
    }
    match balance_wei {
        Some(b) if b >= required_wei => Funding::Met,
        Some(b) => Funding::Short {
            required_wei,
            shortfall_wei: required_wei - b,
            balance_unknown: false,
        },
        None => Funding::Short {
            required_wei,
            shortfall_wei: required_wei,
            balance_unknown: true,
        },
    }
}

/// The stake or bond a role set needs in total, in wei. `validator_stake_wei`
/// replaces the protocol minimum for the validator when the user chose more.
pub fn required_stake_wei(roles: &RoleSet, validator_stake_wei: u128) -> u128 {
    roles
        .iter()
        .filter_map(requirement_of)
        .map(|r| {
            if r.role == "validator" {
                r.stake_wei.max(validator_stake_wei)
            } else {
                r.stake_wei
            }
        })
        .sum()
}

/// The line that says testnet tokens carry no monetary value.
pub const TESTNET_VALUE_LINE: &str = "Testnet tokens have no monetary value.";

/// How to continue later from the funding step.
pub const RESUME_HINT: &str = "Your progress is saved. Run `tenzro setup` again at any time and it resumes at the funding step.";

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(key: bool, delegate: Option<&str>) -> AuthorityFacts {
        AuthorityFacts {
            machine_key_available: key,
            machine_key_reason: "no TPM detected on this machine".into(),
            delegate_machine: delegate.map(str::to_string),
        }
    }

    fn big() -> MachineFacts {
        MachineFacts {
            ram_gb: 64.0,
            storage_gb: 500.0,
            accelerator: true,
            hardware_key: true,
        }
    }

    fn never(_: &str, _: &[String]) -> Result<usize> {
        panic!("a flag must skip the prompt");
    }

    #[test]
    fn the_tpm_option_is_hidden_without_a_tpm() {
        assert_eq!(
            authority_options(&facts(false, None)),
            vec![Authority::Passkey]
        );
        assert_eq!(
            authority_options(&facts(true, None)),
            vec![Authority::Passkey, Authority::MachineKey]
        );
    }

    #[test]
    fn the_delegated_option_needs_a_named_tpm_machine() {
        assert_eq!(
            authority_options(&facts(false, Some("alice"))),
            vec![Authority::Passkey, Authority::Delegated]
        );
        assert!(!authority_options(&facts(true, Some("alice"))).contains(&Authority::Delegated));
    }

    #[test]
    fn flags_override_prompts() {
        let f = facts(true, None);
        let c = resolve_choice(Some("self"), &f, &mut never).unwrap();
        assert_eq!(
            (c.authority, c.mode),
            (Authority::Passkey, OperationMode::Human)
        );
        let c = resolve_choice(Some("autonomous"), &f, &mut never).unwrap();
        assert_eq!(
            (c.authority, c.mode),
            (Authority::MachineKey, OperationMode::Autonomous)
        );
        let c = resolve_choice(Some("agentic"), &f, &mut never).unwrap();
        assert_eq!(
            (c.authority, c.mode),
            (Authority::Passkey, OperationMode::Agentic)
        );
    }

    #[test]
    fn autonomous_flag_without_a_tpm_says_what_and_how_to_fix() {
        let e = resolve_choice(Some("autonomous"), &facts(false, None), &mut never)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no TPM detected") && e.contains("Fix:"), "{e}");
    }

    #[test]
    fn an_unknown_operator_flag_is_refused() {
        assert!(resolve_choice(Some("robot"), &facts(true, None), &mut never).is_err());
    }

    #[test]
    fn without_a_flag_the_user_is_asked_and_the_answer_is_used() {
        let mut asked = Vec::new();
        let mut ask = |q: &str, opts: &[String]| -> Result<usize> {
            asked.push((q.to_string(), opts.len()));
            Ok(1)
        };
        let c = resolve_choice(None, &facts(true, None), &mut ask).unwrap();
        assert_eq!(
            (c.authority, c.mode),
            (Authority::MachineKey, OperationMode::Autonomous)
        );
        // Authority was asked (two options); the chip has one mode, so no second question.
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].1, 2);
    }

    #[test]
    fn a_machine_without_a_chip_goes_straight_to_the_passkey_modes() {
        let mut ask = |q: &str, opts: &[String]| -> Result<usize> {
            assert!(q.contains("operated"), "only the mode is asked: {q}");
            assert_eq!(opts.len(), 2);
            Ok(1)
        };
        let c = resolve_choice(None, &facts(false, None), &mut ask).unwrap();
        assert_eq!(c.mode, OperationMode::Agentic);
    }

    #[test]
    fn every_authority_says_what_losing_it_means() {
        for a in [
            Authority::Passkey,
            Authority::MachineKey,
            Authority::Delegated,
        ] {
            assert!(
                a.loss_line().contains("lose") || a.loss_line().contains("lost"),
                "{a:?}"
            );
        }
    }

    #[test]
    fn modes_map_to_their_evidence() {
        assert_eq!(
            OperationMode::Human.required_evidence(),
            Evidence::PasskeyAssertion
        );
        assert_eq!(
            OperationMode::Autonomous.required_evidence(),
            Evidence::HardwareQuote
        );
        assert_eq!(
            OperationMode::Agentic.required_evidence(),
            Evidence::DelegationCredential
        );
    }

    #[test]
    fn a_label_alone_is_refused_and_grants_nothing() {
        for m in [
            OperationMode::Human,
            OperationMode::Autonomous,
            OperationMode::Agentic,
        ] {
            assert_eq!(verify_claim(m, &[]), Err(ClaimError::LabelOnly(m)));
        }
        let msg = ClaimError::LabelOnly(OperationMode::Autonomous).to_string();
        assert!(
            msg.contains("grants no permissions") && msg.contains("hardware_quote"),
            "{msg}"
        );
    }

    #[test]
    fn evidence_of_another_kind_does_not_prove_the_mode() {
        assert_eq!(
            verify_claim(OperationMode::Autonomous, &[Evidence::PasskeyAssertion]),
            Err(ClaimError::WrongEvidence(OperationMode::Autonomous))
        );
        assert_eq!(
            verify_claim(OperationMode::Agentic, &[Evidence::DelegationCredential]),
            Ok(Evidence::DelegationCredential)
        );
    }

    fn terms() -> AgentDelegation {
        AgentDelegation {
            delegator: format!("0x{}", "ab".repeat(32)),
            scopes: vec!["inference".into()],
            max_transaction_wei: 10,
            max_daily_wei: 100,
            expires_in_hours: 24,
        }
    }

    #[test]
    fn agentic_requires_a_delegator() {
        let mut t = terms();
        assert!(t.validate().is_ok());
        t.delegator = "  ".into();
        let e = t.validate().unwrap_err().to_string();
        assert!(
            e.contains("needs a delegator") && e.contains("--delegator"),
            "{e}"
        );
    }

    #[test]
    fn an_agent_cannot_be_the_delegator() {
        let mut t = terms();
        t.delegator = "did:tenzro:machine:abc".into();
        assert!(
            t.validate()
                .unwrap_err()
                .to_string()
                .contains("not a human identity")
        );
    }

    #[test]
    fn a_delegation_needs_scopes_a_limit_and_an_expiry() {
        let mut t = terms();
        t.scopes = vec!["*".into()];
        assert!(t.validate().is_err());
        let mut t = terms();
        t.max_daily_wei = 0;
        assert!(t.validate().is_err());
        let mut t = terms();
        t.max_transaction_wei = 1000;
        assert!(t.validate().is_err());
        let mut t = terms();
        t.expires_in_hours = 0;
        assert!(t.validate().is_err());
        t.expires_in_hours = MAX_DELEGATION_HOURS + 1;
        assert!(t.validate().is_err());
    }

    #[test]
    fn the_delegation_converts_to_the_identity_scope() {
        let s = terms().to_scope();
        assert_eq!(s.allowed_operations, vec!["inference".to_string()]);
        assert_eq!(s.max_daily_spend, Some(100));
        assert!(s.time_bound.is_some());
    }

    #[test]
    fn the_mode_record_names_its_evidence_in_the_agent_card() {
        let r = ModeRecord::new(OperationMode::Agentic, Some("did:tenzro:human:x".into()));
        let v = r.agent_card_extension();
        assert_eq!(v["uri"], AGENT_CARD_MODE_EXTENSION);
        assert_eq!(v["params"]["mode"], "agentic");
        assert_eq!(v["params"]["evidence"], "delegation_credential");
        assert_eq!(v["params"]["delegator"], "did:tenzro:human:x");
    }

    #[test]
    fn personas_map_onto_the_role_machinery() {
        assert_eq!(Persona::Participant.roles(&[]), RoleSet::client());
        assert!(Persona::Validator.roles(&[]).is_validator());
        assert!(Persona::RpcProvider.roles(&[]).has(NetworkRole::Rpc));
        assert!(Persona::Operator.roles(&[]).has(NetworkRole::ModelProvider));
        let s = Persona::Operator.roles(&[NetworkRole::StorageProvider]);
        assert!(s.has(NetworkRole::StorageProvider) && !s.has(NetworkRole::ModelProvider));
        assert_eq!(
            Persona::from_mode_flag("consume"),
            Some(Persona::Participant)
        );
        assert_eq!(Persona::from_mode_flag("provide"), Some(Persona::Operator));
        assert_eq!(
            Persona::from_mode_flag("validate"),
            Some(Persona::Validator)
        );
        assert_eq!(
            Persona::of_roles(&RoleSet::from(NetworkRole::Rpc)),
            Persona::RpcProvider
        );
    }

    #[test]
    fn a_participant_meets_every_requirement_and_needs_no_stake() {
        let tiny = MachineFacts {
            ram_gb: 1.0,
            storage_gb: 1.0,
            accelerator: false,
            hardware_key: false,
        };
        assert!(persona_gate(Persona::Participant, &[], &tiny).is_ok());
        let stake = required_stake_wei(&Persona::Participant.roles(&[]), 0);
        assert_eq!(funding_decision(stake, Some(0)), Funding::NotNeeded);
    }

    #[test]
    fn requirements_gate_each_persona_and_say_how_to_fix() {
        let pi = MachineFacts {
            ram_gb: 4.0,
            storage_gb: 30.0,
            accelerator: false,
            hardware_key: false,
        };
        let err = persona_gate(Persona::Validator, &[], &pi).unwrap_err();
        assert!(err.iter().any(|u| u.what.contains("memory")));
        assert!(err.iter().any(|u| u.what.contains("free storage")));
        assert!(err.iter().any(|u| u.what.contains("TPM")));
        assert!(err.iter().all(|u| !u.fix.is_empty()));
        assert!(persona_gate(Persona::Operator, &[NetworkRole::ModelProvider], &pi).is_err());
        assert!(persona_gate(Persona::RpcProvider, &[], &pi).is_err());
        assert!(persona_gate(Persona::Validator, &[], &big()).is_ok());
    }

    #[test]
    fn eligibility_follows_measurements_not_device_class() {
        // A small ARM board that measures up is eligible; the gate has no
        // other input to tell it apart from a server.
        let board = MachineFacts {
            ram_gb: 8.0,
            storage_gb: 128.0,
            accelerator: false,
            hardware_key: false,
        };
        assert!(persona_gate(Persona::RpcProvider, &[], &board).is_ok());
        assert!(persona_gate(Persona::Operator, &[NetworkRole::StorageProvider], &board).is_ok());
    }

    #[test]
    fn an_operator_is_offered_when_one_service_fits() {
        let storage_box = MachineFacts {
            ram_gb: 4.0,
            storage_gb: 500.0,
            accelerator: false,
            hardware_key: false,
        };
        assert!(persona_availability(Persona::Operator, &storage_box).is_ok());
        assert!(
            persona_gate(
                Persona::Operator,
                &[NetworkRole::ModelProvider],
                &storage_box
            )
            .is_err()
        );
        let nothing = MachineFacts {
            ram_gb: 1.0,
            storage_gb: 10.0,
            accelerator: false,
            hardware_key: false,
        };
        let err = persona_availability(Persona::Operator, &nothing).unwrap_err();
        assert!(!err.is_empty() && err.iter().all(|u| !u.fix.is_empty()));
    }

    #[test]
    fn gate_roles_names_every_unmet_requirement() {
        let small = MachineFacts {
            ram_gb: 2.0,
            storage_gb: 500.0,
            accelerator: false,
            hardware_key: true,
        };
        let e = gate_roles(&Persona::Validator.roles(&[]), &small)
            .unwrap_err()
            .to_string();
        assert!(e.contains("memory") && e.contains("Fix:"), "{e}");
        assert!(gate_roles(&Persona::Validator.roles(&[]), &big()).is_ok());
    }

    #[test]
    fn each_persona_line_states_its_requirements() {
        assert!(requirement_line(Persona::Participant, &[]).contains("no stake"));
        let v = requirement_line(Persona::Validator, &[]);
        assert!(
            v.contains("always on") && v.contains("bond of 10000 TNZO") && v.contains("TPM"),
            "{v}"
        );
        let r = requirement_line(Persona::RpcProvider, &[]);
        assert!(r.contains("bond of 100000 TNZO"), "{r}");
    }

    #[test]
    fn funding_is_needed_only_below_the_stake() {
        let one = tenzro_types::constants::ONE_TNZO;
        assert_eq!(funding_decision(0, Some(0)), Funding::NotNeeded);
        assert_eq!(funding_decision(10 * one, Some(10 * one)), Funding::Met);
        assert_eq!(
            funding_decision(10 * one, Some(4 * one)),
            Funding::Short {
                required_wei: 10 * one,
                shortfall_wei: 6 * one,
                balance_unknown: false
            }
        );
        assert_eq!(
            funding_decision(10 * one, None),
            Funding::Short {
                required_wei: 10 * one,
                shortfall_wei: 10 * one,
                balance_unknown: true
            }
        );
    }

    #[test]
    fn the_stake_of_a_role_set_is_the_sum_of_its_bonds() {
        let one = tenzro_types::constants::ONE_TNZO;
        assert_eq!(required_stake_wei(&RoleSet::client(), 0), 0);
        assert_eq!(
            required_stake_wei(&Persona::RpcProvider.roles(&[]), 0),
            100_000 * one
        );
        assert_eq!(
            required_stake_wei(&Persona::Validator.roles(&[]), 20_000 * one),
            20_000 * one
        );
        let both =
            Persona::Operator.roles(&[NetworkRole::ModelProvider, NetworkRole::StorageProvider]);
        assert_eq!(required_stake_wei(&both, 0), 1_100 * one);
    }

    #[test]
    fn admission_closed_refuses_the_validator_role_and_offers_the_open_ones() {
        let closed =
            Admission::from_reply(&serde_json::json!({"mode": "closed", "admitted": false}));
        assert!(closed.refuses_validator());
        let err = gate_admission(&Persona::Validator.roles(&[]), &closed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("closed while the network stabilises"), "{err}");
        assert!(err.contains("operator or a participant"), "{err}");
        assert!(err.contains("team@tenzro.com"), "{err}");
        assert!(err.contains("Why:") && err.contains("Fix:"), "{err}");
        assert!(
            gate_admission(
                &Persona::Operator.roles(&[NetworkRole::StorageProvider]),
                &closed
            )
            .is_ok()
        );
        assert!(gate_admission(&Persona::Participant.roles(&[]), &closed).is_ok());
        assert!(
            admission_menu_note(Persona::Validator, &closed)
                .unwrap()
                .contains("operator or participant")
        );
        assert!(admission_menu_note(Persona::Operator, &closed).is_none());
    }

    #[test]
    fn admission_open_admitted_or_unreadable_refuses_nothing() {
        let open = Admission::from_reply(&serde_json::json!({"mode": "open", "admitted": true}));
        let admitted =
            Admission::from_reply(&serde_json::json!({"mode": "closed", "admitted": true}));
        let unknown = Admission::from_reply(&serde_json::json!({"error": "x"}));
        assert_eq!(unknown, Admission::Unknown);
        for a in [open, admitted, unknown] {
            assert!(!a.refuses_validator());
            assert!(gate_admission(&Persona::Validator.roles(&[]), &a).is_ok());
            assert!(admission_menu_note(Persona::Validator, &a).is_none());
        }
    }

    #[test]
    fn the_steps_are_numbered_and_resume_where_they_stopped() {
        assert_eq!(Step::Role.progress_line(), "Step 3 of 7: Role");
        let mut r = WizardRecord::default();
        assert_eq!(r.resume_step(), Step::Name);
        assert!(r.complete(Step::Role));
        assert_eq!(r.resume_step(), Step::Funding);
        assert!(r.is_done(Step::Role) && !r.is_done(Step::Funding));
        let json = serde_json::to_string(&r).unwrap();
        let back: WizardRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resume_step(), Step::Funding);
        assert!(!r.complete(Step::Service));
    }

    #[test]
    fn an_unreadable_record_starts_over() {
        let r = WizardRecord {
            next: "garbage".into(),
            ..Default::default()
        };
        assert_eq!(r.resume_step(), Step::Name);
    }

    #[test]
    fn the_record_holds_no_key_material() {
        let r = WizardRecord {
            next: "funding".into(),
            funding_account: Some("0xabc".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&r).unwrap().to_lowercase();
        assert!(!json.contains("private") && !json.contains("secret"));
    }
}
