//! Guided setup wizard.
//!
//! `tenzro setup` walks a new participant through hardware detection and
//! one of three paths:
//!
//! 1. **Join the Tenzro network** — consume models and services, provide
//!    inference from this machine, or run a validator on the public
//!    network. Wraps the existing `tenzro join` RPC flow.
//! 2. **Create a local or sovereign network** — generate a founding
//!    validator keyset, assemble a genesis v3 file, and print the exact
//!    start command for this machine plus a join command for every peer.
//! 3. **Join an existing private network** — point at a genesis file and
//!    the boot identity supplied by the network operator.
//!
//! Every interactive prompt is mirrored by a flag so the wizard is fully
//! scriptable (`--yes` accepts defaults and never prompts).

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::Parser;
use console::{Style, style};
use dialoguer::{Input, MultiSelect, Select, theme::ColorfulTheme};
use rand::Rng;
use tenzro_types::network::{NetworkRole, RoleSet};

use crate::commands::hardware::{HardwareProfile, detect_hardware_profile};
use crate::commands::join::JoinCmd;
use crate::commands::preflight;
use crate::commands::service;
use crate::commands::stake_options::{self, LineKind, StakeNeed};
use crate::commands::update::install::Layout;
use crate::config;
use crate::onboarding::wizard::{
    Admission, AgentDelegation, Authority, AuthorityFacts, Funding, MachineFacts,
    OPERATOR_SERVICES, OperationMode, PERSONAS, Persona, RESUME_HINT, Step, TESTNET_VALUE_LINE,
    WizardRecord, admission_menu_note, admission_refusal, funding_decision, gate_admission,
    gate_roles, persona_availability, required_stake_wei, requirement_line, resolve_choice,
};

/// Guided setup — join the network, provide, validate, or bootstrap a
/// private network.
#[derive(Debug, Parser)]
pub struct SetupCmd {
    /// Setup path: "network" (join the public Tenzro network), "local"
    /// (create a local or sovereign network), or "private" (join an
    /// existing private network).
    #[arg(long, value_parser = ["network", "local", "private"])]
    pub path: Option<String>,

    /// RPC endpoint override for identity provisioning.
    #[arg(long)]
    pub rpc: Option<String>,

    /// Display name for identity provisioning.
    #[arg(long)]
    pub name: Option<String>,

    /// Participation mode on the public network. A shorthand for `--roles`:
    /// `consume` selects no serving role, `provide` selects the AI provider
    /// role, `validate` selects the validator role. `--roles` wins when both
    /// are given, since it says strictly more.
    #[arg(long, value_parser = ["consume", "provide", "validate"])]
    pub mode: Option<String>,

    /// Machine name — a label of 3-63 characters, `[a-z0-9-]`, not starting
    /// or ending with a hyphen.
    #[arg(long)]
    pub machine_name: Option<String>,

    /// Whether this node is reachable from the public internet, or stays
    /// reachable only on the local network.
    #[arg(long, value_parser = ["public", "private"])]
    pub visibility: Option<String>,

    /// How the node is operated: `self` (a human holds the passkey and
    /// approves actions), `autonomous` (the machine answers for itself via
    /// its TPM 2.0 or Secure Enclave) or `agentic` (an AI agent operates the
    /// node under a delegation from a human passkey). Without it an
    /// interactive run asks.
    #[arg(long, value_parser = ["self", "autonomous", "agentic"])]
    pub operator: Option<String>,

    /// Who delegates to the agent in `--operator agentic`: a
    /// `did:tenzro:human:` identity or a 0x account.
    #[arg(long)]
    pub delegator: Option<String>,

    /// Operations an agent may perform, comma-separated. Defaults to
    /// `inference`.
    #[arg(long)]
    pub delegation_scopes: Option<String>,

    /// Most an agent may spend per day: TNZO (`10`, `10 TNZO`) or wei with its
    /// suffix. Defaults to 10 TNZO.
    #[arg(long, value_parser = crate::units::parse_amount_wei)]
    pub delegation_limit: Option<u128>,

    /// Hours until the agent's delegation expires.
    #[arg(long, default_value_t = 24)]
    pub delegation_hours: u32,

    /// Discard the saved place of an unfinished setup and start over.
    #[arg(long)]
    pub restart: bool,

    /// Comma-separated roles this node serves, e.g.
    /// `validator,ai,storage`.
    #[arg(long)]
    pub roles: Option<String>,

    /// Comma-separated access models offered for provided resources:
    /// `on-demand`, `subscription`, `rental`.
    #[arg(long)]
    pub access: Option<String>,

    /// Name for a new local or sovereign network.
    #[arg(long)]
    pub network_name: Option<String>,

    /// Chain id for a new local or sovereign network. Defaults to a
    /// random five-digit id, so it collides with neither the local
    /// developer chain (1337) nor the preview network (13380).
    #[arg(long)]
    pub chain_id: Option<u64>,

    /// Node data directory. Defaults depend on the chosen path. Also
    /// settable via `$TENZRO_DATA_DIR`, the same variable `tenzro-node`
    /// itself reads, so a setup and the node it bootstraps agree on where
    /// state lives without repeating the flag.
    #[arg(long, env = "TENZRO_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Genesis stake for the founding validator (whole TNZO units).
    #[arg(long, default_value_t = 1000)]
    pub stake: u64,

    /// Self-stake a public-network validator registers with: TNZO (`10000`,
    /// `10000 TNZO`) or wei with its suffix. The network's minimum is the
    /// governed `stake.validator_tnzo` (10,000 TNZO at genesis).
    #[arg(long, default_value = "10000", value_parser = crate::units::parse_amount_wei)]
    pub validator_stake: u128,

    /// Boot identity of an existing private network, as its operator prints
    /// it: `did:tenzro:machine:<id>@<relay url>`. Several, separated by
    /// commas, name several relays; the node moves to another when one stops.
    #[arg(long)]
    pub bootstrap: Option<String>,

    /// Path to the genesis.toml of an existing private network.
    #[arg(long)]
    pub genesis: Option<PathBuf>,

    /// Create this machine's TPM keys with `tenzro-node tpm provision`
    /// without asking, when the preflight finds they are missing. Without
    /// this flag the wizard asks, and a non-interactive run stops and prints
    /// the command. Implied by --apply.
    #[arg(long)]
    pub provision_tpm: bool,

    /// After setup, install the node as a service, start it, and follow it
    /// until it has synced. On Linux this runs `sudo` for the systemd unit;
    /// on macOS it loads a launch agent. Interactive runs are asked instead.
    #[arg(long)]
    pub apply: bool,

    /// Non-interactive: accept defaults, take everything else from flags.
    #[arg(long)]
    pub yes: bool,

    /// Use the line-by-line wizard instead of the full-screen setup, even on
    /// a terminal.
    #[arg(long)]
    pub plain: bool,
}

impl SetupCmd {
    /// Whether this run should open the full-screen setup: a terminal, and
    /// nothing asked for the line-by-line wizard or answered its questions.
    pub fn wants_full_screen(&self) -> bool {
        !self.plain
            && !self.yes
            && self.path.is_none()
            && self.mode.is_none()
            && self.roles.is_none()
            && crate::tui::available()
    }

    pub async fn execute(&self) -> Result<()> {
        if self.wants_full_screen() {
            let rpc = self.rpc.clone().unwrap_or_else(crate::tui::first_run_rpc);
            let outcome = crate::tui::first_run(rpc).await?;
            if let Some(text) = crate::tui::farewell(&outcome) {
                println!("{text}");
            }
            return Ok(());
        }
        wiz_intro();

        let interactive = !self.yes && std::io::IsTerminal::is_terminal(&std::io::stdin());

        // Step 1 — detect what this machine can do.
        let detecting = crate::progress::global().wait(
            "Detecting hardware",
            "reading the processor, memory, disks and security chip",
        );
        let hw = detect_hardware_profile().await;
        detecting.dismiss();
        wiz_section("Hardware");
        print_hardware_summary(&hw);
        wiz_gap();

        // Step 2 — choose a path. Joining the public network leads.
        let path = match self.path.as_deref() {
            Some(p) => p.to_string(),
            None => {
                let items = [
                    "Join the Tenzro network (consume, provide, or validate)",
                    "Create a local or sovereign network",
                    "Join an existing private network",
                ];
                match prompt_select(interactive, "What would you like to set up?", &items, 0)? {
                    1 => "local".to_string(),
                    2 => "private".to_string(),
                    _ => "network".to_string(),
                }
            }
        };

        match path.as_str() {
            "local" => self.run_local_path(interactive, &hw).await,
            "private" => self.run_private_path(interactive, &hw).await,
            _ => self.run_network_path(interactive, &hw).await,
        }
    }

    // ------------------------------------------------------------------
    // Path 1 — public Tenzro network
    // ------------------------------------------------------------------

    /// Public-network path: one sequence of seven steps, each with a progress
    /// line and each saved so `tenzro setup` resumes where it stopped.
    ///
    /// 1. **Name** - display name and machine name.
    /// 2. **Authority** - who holds the identity and wallet key (a passkey, or
    ///    this machine's TPM / Secure Enclave) and how the node is operated.
    ///    Blocking: the wallet is created here, from the chosen authority's key
    ///    material, and never before. This process holds no wallet private key.
    /// 3. **Role** - participant, operator, validator or RPC provider, gated
    ///    by what the machine measures at.
    /// 4. **Funding** - when the role bonds and the wallet holds less.
    /// 5. **Reachability** - public or local network only.
    /// 6. **Access** - how a provider offers what it serves.
    /// 7. **Service** - install, start and follow the node until it has synced.
    async fn run_network_path(&self, interactive: bool, hw: &HardwareProfile) -> Result<()> {
        let mut rec = if self.restart {
            WizardRecord::default()
        } else {
            self.load_cfg().wizard.unwrap_or_default()
        };
        if rec.next.is_empty() {
            rec.next = Step::Name.slug().to_string();
        }
        if rec.resume_step() != Step::Name {
            wiz_note(&format!(
                "Resuming the setup you started earlier. {}",
                rec.resume_step().progress_line()
            ));
            wiz_gap();
        }
        let anchor = MachineAnchorOptions::detect(hw);
        let machine = MachineFacts::from_profile(hw, anchor.autonomous_available);

        // ---- 1. Name -------------------------------------------------
        let (name, machine_name) = match (&rec.display_name, &rec.machine_name) {
            (Some(n), Some(m)) if rec.is_done(Step::Name) => (n.clone(), m.clone()),
            _ => {
                wiz_section(&Step::Name.progress_line());
                let name = match &self.name {
                    Some(n) => n.clone(),
                    None => prompt_string(interactive, "Display name", "Tenzro User")?,
                };
                wiz_note("A short name for this machine, used to address it on the network.");
                let machine_name = self.resolve_machine_name(interactive)?;
                wiz_kv("Name", &name);
                wiz_kv("Machine", &machine_name);
                wiz_gap();
                rec.display_name = Some(name.clone());
                rec.machine_name = Some(machine_name.clone());
                rec.complete(Step::Name);
                self.save_wizard(&rec)?;
                (name, machine_name)
            }
        };

        // ---- 2. Authority (identity and wallet, blocking) --------------
        let stored = rec
            .authority
            .as_deref()
            .and_then(Authority::parse)
            .zip(rec.mode.as_deref().and_then(OperationMode::parse));
        let (authority, mode) = match stored {
            Some(done) if rec.is_done(Step::Authority) => done,
            _ => {
                wiz_section(&Step::Authority.progress_line());
                let facts = AuthorityFacts {
                    machine_key_available: anchor.autonomous_available,
                    machine_key_reason: anchor.reason.clone(),
                    delegate_machine: self.delegate_machine(),
                };
                if !facts.machine_key_available && self.operator.is_none() {
                    wiz_note(&format!(
                        "A TPM / Secure Enclave authority is not offered: {}.",
                        anchor.reason
                    ));
                }
                let choice = resolve_choice(self.operator.as_deref(), &facts, &mut |q, opts| {
                    let items: Vec<&str> = opts.iter().map(String::as_str).collect();
                    prompt_select(interactive, q, &items, 0)
                })?;
                wiz_kv("Authority", choice.authority.explain(&facts).as_str());
                wiz_kv("Operation", choice.mode.explain());
                wiz_note(choice.authority.loss_line());
                rec.authority = Some(choice.authority.slug().to_string());
                rec.mode = Some(choice.mode.slug().to_string());

                if choice.mode == OperationMode::Agentic {
                    if !self.agent_delegation_ready(interactive, &mut rec)? {
                        return Ok(());
                    }
                } else if choice.authority == Authority::Passkey {
                    wiz_section("Identity and wallet");
                    wiz_note(
                        "This opens the Tenzro wallet page: a link and a QR code are printed, and your browser is opened when this machine has one.",
                    );
                    wiz_note(
                        "The passkey and the wallet key stay in your authenticator; nothing is stored on this machine.",
                    );
                    let join = JoinCmd {
                        rpc: self.rpc.clone(),
                        name: name.clone(),
                        origin: "cli".to_string(),
                        r#type: "human".to_string(),
                        // Provider registration, bond and pricing follow the
                        // role and funding steps, once the role is known.
                        provider: false,
                        role: None,
                        wallet: None,
                    };
                    join.execute().await?;
                } else {
                    self.register_machine_identity(interactive, hw, &name)
                        .await?;
                }
                wiz_done("Identity and wallet ready");
                wiz_gap();
                let delegator = rec.delegator.clone();
                self.update_cfg(|c| {
                    c.operator_mode = Some(choice.mode.slug().to_string());
                    c.authority = Some(choice.authority.slug().to_string());
                    c.delegator = delegator;
                })?;
                rec.complete(Step::Authority);
                self.save_wizard(&rec)?;
                (choice.authority, choice.mode)
            }
        };

        // ---- 3. Role ---------------------------------------------------
        let roles = match rec.roles.as_deref().map(str::parse::<RoleSet>) {
            Some(Ok(r)) if rec.is_done(Step::Role) => r,
            _ => {
                wiz_section(&Step::Role.progress_line());
                let admission = self.read_admission(&rec).await;
                let r = self.resolve_roles(interactive, &machine, &admission)?;
                wiz_kv("Role", Persona::of_roles(&r).label());
                wiz_kv("Serving", &r.to_string());
                wiz_gap();
                rec.roles = Some(r.to_string());
                rec.complete(Step::Role);
                self.save_wizard(&rec)?;
                r
            }
        };

        // ---- 4. Funding ------------------------------------------------
        if !rec.is_done(Step::Funding) {
            wiz_section(&Step::Funding.progress_line());
            if !self
                .run_funding(interactive, &mut rec, &roles, authority)
                .await?
            {
                return Ok(());
            }
            // Provider registration, bond and pricing, for anyone serving a
            // paid role through a passkey identity.
            if roles.is_provider() && authority == Authority::Passkey {
                crate::commands::join::provider_setup(
                    &self
                        .rpc
                        .clone()
                        .unwrap_or_else(|| "https://rpc.tenzro.com".to_string()),
                    &name,
                )
                .await?;
            }
            wiz_gap();
            rec.complete(Step::Funding);
            self.save_wizard(&rec)?;
        }

        // ---- 5. Reachability -------------------------------------------
        let public = if rec.is_done(Step::Reachability) {
            self.load_cfg().public.unwrap_or(false)
        } else {
            wiz_section(&Step::Reachability.progress_line());
            let public = match self.visibility.as_deref() {
                Some(v) => v == "public",
                None => {
                    let items = [
                        "Private — reachable on your local network only",
                        "Public — also reachable from the internet",
                    ];
                    prompt_select(interactive, "How should this node be reachable?", &items, 0)?
                        == 1
                }
            };
            if public {
                wiz_kv("Reachable", "Public + local network");
            } else {
                wiz_kv("Reachable", "Local network only");
                wiz_note("You can turn public access on later.");
            }
            wiz_gap();
            self.update_cfg(|c| c.public = Some(public))?;
            rec.complete(Step::Reachability);
            self.save_wizard(&rec)?;
            public
        };

        // ---- 6. Access model -------------------------------------------
        // Only meaningful for a node that actually provides something; a
        // pure client or validator has nothing to price.
        let access: Vec<String> = if rec.is_done(Step::Access) {
            self.load_cfg()
                .access_models
                .map(|a| a.split(',').map(str::to_string).collect())
                .unwrap_or_default()
        } else if roles.is_provider() {
            wiz_section(&Step::Access.progress_line());
            let a = self.resolve_access_models(interactive)?;
            wiz_kv("Offered as", &a.join(", "));
            wiz_gap();
            rec.complete(Step::Access);
            self.save_wizard(&rec)?;
            a
        } else {
            wiz_note(&format!(
                "{}: nothing to offer, skipped.",
                Step::Access.progress_line()
            ));
            rec.complete(Step::Access);
            self.save_wizard(&rec)?;
            Vec::new()
        };

        self.persist_setup(&name, &machine_name, public, mode, &roles, &access)?;

        // ---- 7. Service ------------------------------------------------
        wiz_section(&Step::Service.progress_line());
        wiz_note(&format!(
            "Summary: {} ({}) | authority {} | operation {} | roles {} | {}",
            name,
            machine_name,
            authority.slug(),
            mode.slug(),
            roles,
            if public {
                "public"
            } else {
                "local network only"
            }
        ));
        if roles.is_validator() {
            self.run_public_validator(interactive, &name, hw).await?;
            self.clear_wizard()?;
            return Ok(());
        }

        let data_dir = match &self.data_dir {
            Some(d) => tenzro_types::paths::expand_tilde(d),
            None => tenzro_types::paths::default_data_dir(),
        };
        if self.wants_apply(interactive)? {
            let unit = write_service_unit(&data_dir, None, None, &roles.to_string(), &[])?;
            self.apply_service(interactive, hw, &unit, authority != Authority::Passkey)
                .await?;
        } else {
            wiz_section("Next steps");
            wiz_note("Start the node with:");
            wiz_cmd(&[format!("tenzro node start --roles {roles}")]);
        }
        self.clear_wizard()?;
        wiz_outro("Setup complete");
        Ok(())
    }

    /// The config this run reads and writes: scoped to `--data-dir` when
    /// given, the global one otherwise.
    fn load_cfg(&self) -> config::PersistedConfig {
        match self
            .data_dir
            .as_ref()
            .map(tenzro_types::paths::expand_tilde)
        {
            Some(dir) => config::load_config_in(&dir),
            None => config::load_config(),
        }
    }

    /// Load, change and save the config this run uses.
    fn update_cfg(&self, f: impl FnOnce(&mut config::PersistedConfig)) -> Result<()> {
        let mut cfg = self.load_cfg();
        f(&mut cfg);
        match self
            .data_dir
            .as_ref()
            .map(tenzro_types::paths::expand_tilde)
        {
            Some(dir) => config::save_config_in(&dir, &cfg),
            None => config::save_config(&cfg),
        }
    }

    /// Keep the wizard's place so `tenzro setup` resumes there.
    fn save_wizard(&self, rec: &WizardRecord) -> Result<()> {
        self.update_cfg(|c| c.wizard = Some(rec.clone()))
    }

    /// Forget the wizard's place: the setup finished.
    fn clear_wizard(&self) -> Result<()> {
        self.update_cfg(|c| c.wizard = None)
    }

    /// A TPM machine on the network that can hold this machine's key, when
    /// one was configured (the key holder grant of the first-run console).
    fn delegate_machine(&self) -> Option<String> {
        let cfg = self.load_cfg();
        match (cfg.key_holder_socket, cfg.key_holder_label) {
            (Some(_), Some(label)) => Some(label),
            _ => None,
        }
    }

    /// Anchor this machine's identity in its TPM or Secure Enclave. The key is
    /// created inside the chip; only the public half leaves it, and the
    /// machine registers its own identity and wallet bound to that key. A
    /// human passkey can be attached later as recovery or co-authority: the
    /// identity record is a hardware-rooted one, which leaves room for it.
    async fn register_machine_identity(
        &self,
        interactive: bool,
        hw: &HardwareProfile,
        name: &str,
    ) -> Result<()> {
        self.run_preflight(interactive, hw)?;
        wiz_section("Identity and wallet");
        // A scoped run (--data-dir, or $TENZRO_DATA_DIR) says which node to
        // register on, and registers there; it can never skip this step.
        let rpc_url = autonomous_identity_rpc(self.rpc.as_deref(), self.data_dir.is_some())?;
        // `registerIdentity` with `identity_type: "autonomous"` is the
        // primitive that collects the hardware identity, refuses when it is
        // not attestable, and anchors the machine as `HardwareRooted`.
        wiz_note("Registering this machine against its hardware root...");
        let rpc = crate::rpc::RpcClient::new(&rpc_url);
        let registering = crate::progress::global().wait(
            "Registering the machine identity",
            "waiting for the hardware key to sign",
        );
        let reply: Result<serde_json::Value, _> = rpc
            .call(
                "tenzro_registerIdentity",
                serde_json::json!({
                    "identity_type": "autonomous",
                    "display_name": name,
                }),
            )
            .await;
        let result: serde_json::Value = match reply {
            Ok(r) => {
                registering.dismiss();
                r
            }
            Err(e) => {
                registering.fail(&e.to_string());
                return Err(anyhow!(
                    "autonomous registration failed: {e}\n\
                     The machine must present an attestable hardware root; \
                     re-run with --operator self to use a passkey instead."
                ));
            }
        };
        if let Some(did) = result
            .get("identity")
            .and_then(|i| i.get("did"))
            .and_then(|v| v.as_str())
        {
            wiz_kv("Machine DID", did);
        }
        Ok(())
    }

    /// The agentic mode: an agent operates the node under a delegation from a
    /// human passkey, and never holds a root key. The wizard asks who
    /// delegates, writes the terms, and prints the two commands that put the
    /// delegator's passkey signature on them. Returns `true` when the agent
    /// identity already exists (a resumed run), `false` after pausing for the
    /// delegator, with the place saved.
    fn agent_delegation_ready(&self, interactive: bool, rec: &mut WizardRecord) -> Result<bool> {
        let delegator = match self.delegator.clone().or_else(|| rec.delegator.clone()) {
            Some(d) => d,
            None => prompt_string(
                interactive,
                "Who delegates? (a did:tenzro:human:... identity or a 0x account)",
                "",
            )?,
        };
        let daily = self
            .delegation_limit
            .unwrap_or(10 * tenzro_types::constants::ONE_TNZO);
        let terms = AgentDelegation {
            delegator: delegator.trim().to_string(),
            scopes: self
                .delegation_scopes
                .as_deref()
                .unwrap_or("inference")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            max_transaction_wei: (daily / 10).max(1),
            max_daily_wei: daily,
            expires_in_hours: self.delegation_hours,
        };
        terms.validate()?;
        rec.delegator = Some(terms.delegator.clone());
        wiz_kv("Delegator", &terms.delegator);
        wiz_kv("Scopes", &terms.scopes.join(", "));
        wiz_kv(
            "Spending limit",
            &format!(
                "{} per day, {} per transaction",
                crate::rpc::format_tnzo(terms.max_daily_wei),
                crate::rpc::format_tnzo(terms.max_transaction_wei)
            ),
        );
        wiz_kv("Expires", &format!("in {} hours", terms.expires_in_hours));

        let cfg = config::load_config();
        if rec.mode.as_deref() == Some("agentic")
            && cfg.did.is_some()
            && cfg.wallet_address.is_some()
        {
            wiz_note("The agent identity exists; carrying on.");
            return Ok(true);
        }

        let path = config::config_path().with_file_name("agent-delegation-terms.json");
        let json = serde_json::to_string_pretty(&terms.to_scope())?;
        std::fs::write(&path, json).map_err(|e| {
            anyhow!(
                "could not write the delegation terms to {}: {e}. Fix: make that directory writable and run `tenzro setup` again.",
                path.display()
            )
        })?;
        let account = if terms.delegator.starts_with("0x") {
            terms.delegator.clone()
        } else {
            "<the 0x account of the delegator>".to_string()
        };
        wiz_note(
            "The delegator approves with their passkey; this machine holds no key for the agent. Run:",
        );
        wiz_cmd(&[format!(
            "tenzro agent delegation challenge delegate --account {account} --terms {}",
            path.display()
        )]);
        wiz_note(
            "Sign the challenge it prints with the delegator's passkey on the wallet page, then create the agent:",
        );
        wiz_cmd(&["tenzro agent delegation onboard --help".to_string()]);
        wiz_warn(
            "Setup is paused until the delegation credential exists. Run `tenzro setup` again afterwards; it resumes here.",
        );
        rec.next = Step::Authority.slug().to_string();
        self.save_wizard(rec)?;
        Ok(false)
    }

    /// The funding step. Returns `true` when the wallet holds what the role
    /// needs (or the role needs nothing) and the setup goes on; `false` when
    /// the user chose to continue later or the wait ran out, with the place
    /// saved so `tenzro setup` resumes here.
    async fn run_funding(
        &self,
        interactive: bool,
        rec: &mut WizardRecord,
        roles: &RoleSet,
        authority: Authority,
    ) -> Result<bool> {
        let mut required = required_stake_wei(roles, self.validator_stake);
        if roles.is_validator() {
            required += VALIDATOR_GAS_RESERVE_WEI;
        }
        if required == 0 {
            wiz_note("A participant needs no stake: nothing to fund.");
            return Ok(true);
        }
        let account = if roles.is_validator() || authority != Authority::Passkey {
            machine_wallet_account().map(|a| format!("0x{}", hex::encode(a))).map_err(|e| {
                anyhow!(
                    "cannot read this machine's wallet account: {e}. \
                     Fix: create the TPM keys with `tenzro-node tpm provision` and run `tenzro setup` again."
                )
            })?
        } else {
            config::load_config().wallet_address.ok_or_else(|| {
                anyhow!(
                    "no wallet address is recorded for this identity, so the funding step cannot name where to send tokens. \
                     Fix: run `tenzro setup --restart` to redo the identity step."
                )
            })?
        };
        let rpc_url = self
            .rpc
            .clone()
            .unwrap_or_else(|| "https://rpc.tenzro.com".to_string());
        rec.funding_account = Some(account.clone());
        rec.funding_required_wei = Some(required.to_string());

        let mut balance = read_balance(&rpc_url, &account).await;
        let Funding::Short {
            shortfall_wei,
            balance_unknown,
            ..
        } = funding_decision(required, balance)
        else {
            wiz_done(&format!(
                "The wallet holds the {} this role needs",
                crate::rpc::format_tnzo(required)
            ));
            stake_options::forget()?;
            return Ok(true);
        };

        wiz_warn(&format!(
            "This role needs {}; the wallet is short by {}{}.",
            crate::rpc::format_tnzo(required),
            crate::rpc::format_tnzo(shortfall_wei),
            if balance_unknown {
                " (its balance could not be read just now)"
            } else {
                ""
            }
        ));
        wiz_kv("Wallet address", &account);
        if let Ok(qr) = crate::onboarding::ceremony::qr_text(&account) {
            println!("{qr}");
        }
        wiz_note(TESTNET_VALUE_LINE);
        let need = StakeNeed {
            role: Persona::of_roles(roles).label().to_ascii_lowercase(),
            required_wei: required,
            balance_wei: balance,
            account: account.clone(),
        };
        need.render(|kind, text| match kind {
            LineKind::Heading => wiz_warn(&text),
            LineKind::Text => wiz_note(&text),
            LineKind::Command => wiz_cmd(&[text]),
        });
        need.remember()?;
        self.save_wizard(rec)?;

        if !interactive {
            wiz_warn(&format!(
                "Setup is paused at the funding step. {RESUME_HINT}"
            ));
            return Ok(false);
        }
        let items = [
            "Wait here until the wallet is funded",
            "Continue later (progress is saved)",
        ];
        if prompt_select(interactive, "What now?", &items, 0)? == 1 {
            wiz_note(RESUME_HINT);
            return Ok(false);
        }

        const POLL: std::time::Duration = std::time::Duration::from_secs(10);
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
        let started = std::time::Instant::now();
        let mut last_shown = None;
        wiz_note("Checking every 10 seconds. Press Ctrl-C to stop; `tenzro setup` resumes here.");
        let waiting = crate::progress::global().wait("Waiting for funds", "checking the wallet");
        loop {
            if matches!(funding_decision(required, balance), Funding::Met) {
                waiting.dismiss();
                wiz_done("Funds received");
                stake_options::forget()?;
                return Ok(true);
            }
            if started.elapsed() >= LIMIT {
                waiting.dismiss();
                wiz_warn(
                    "No funds arrived in 30 minutes, so the setup stops here. Nothing is lost.",
                );
                wiz_note(RESUME_HINT);
                return Ok(false);
            }
            if last_shown != Some(balance) {
                waiting.message(&format!(
                    "the wallet holds {} of {}",
                    balance.map_or_else(
                        || "an unreadable amount".to_string(),
                        crate::rpc::format_tnzo
                    ),
                    crate::rpc::format_tnzo(required)
                ));
                last_shown = Some(balance);
            }
            tokio::time::sleep(POLL).await;
            balance = read_balance(&rpc_url, &account).await;
        }
    }

    /// Whether to install the service and start the node: asked for with
    /// `--apply`, or agreed to at the prompt on an interactive run.
    fn wants_apply(&self, interactive: bool) -> Result<bool> {
        if self.apply {
            return Ok(true);
        }
        if interactive {
            return prompt_confirm("Install the service and start the node now?", true);
        }
        Ok(false)
    }

    /// Install the unit, start the node, and follow it until it has synced.
    /// `preflighted` says the hardware preflight already ran on this path.
    async fn apply_service(
        &self,
        interactive: bool,
        hw: &HardwareProfile,
        unit: &Path,
        preflighted: bool,
    ) -> Result<()> {
        if !preflighted {
            self.run_preflight(interactive, hw)?;
        }
        wiz_section("Service");
        wiz_note("Installing and starting the node service. sudo may ask for your password.");
        service::install(std::env::consts::OS, unit)?;
        wiz_done("Service installed and started");

        wiz_section("Sync");
        match service::follow_sync(LOCAL_RPC, service::FOLLOW_FOR).await? {
            (Some(s), true) => wiz_done(&format!("Caught up: {}", s.describe())),
            (Some(s), false) => {
                wiz_warn(&format!(
                    "Still syncing after {} minutes: {}",
                    service::FOLLOW_FOR.as_secs() / 60,
                    s.describe()
                ));
                wiz_note("Follow it, and see what to do next, with:");
                wiz_cmd(&["tenzro status --watch 2000".to_string()]);
            }
            (None, _) => {
                wiz_warn(&format!(
                    "The node's RPC did not come up within {} minutes.",
                    service::FOLLOW_FOR.as_secs() / 60
                ));
                wiz_note("Read its log:");
                wiz_cmd(&["journalctl -u tenzro-node -n 50 --no-pager".to_string()]);
            }
        }
        Ok(())
    }

    /// Check the machine's hardware root before anything derives a key from
    /// it, and create the TPM keys when the operator agrees.
    ///
    /// Every unmet prerequisite is printed with the lines that fix it. A
    /// blocking one stops the wizard here, where the fix is named, rather
    /// than later as a raw key-derivation error.
    fn run_preflight(&self, interactive: bool, hw: &HardwareProfile) -> Result<()> {
        wiz_section("Preflight");
        let facts = preflight::Facts::probe(has_secure_enclave(hw));
        let checks = preflight::evaluate(&facts);
        preflight::render(&checks, |line| match line {
            preflight::Line::Check(preflight::Level::Pass, text) => wiz_done(&text),
            preflight::Line::Check(preflight::Level::Todo, text) => {
                wiz_note(&format!("To do: {text}"))
            }
            preflight::Line::Check(_, text) => wiz_warn(&text),
            preflight::Line::Fix(text) => wiz_note(&format!("    {text}")),
        });
        if preflight::blocked(&checks) {
            return Err(anyhow!(
                "this machine is not ready: fix the items marked above, then run `tenzro setup` again"
            ));
        }
        if preflight::needs_provision(&checks) {
            let node = facts
                .node_binary
                .as_ref()
                .ok_or_else(|| anyhow!("tenzro-node was not found"))?;
            let agreed = if interactive {
                prompt_confirm(
                    "Create this machine's TPM keys now with `tenzro-node tpm provision`? \
                     (once per machine; keys already in place are kept)",
                    true,
                )?
            } else {
                self.provision_tpm || self.apply
            };
            if !agreed {
                return Err(anyhow!(
                    "this machine's TPM keys have not been created. Run `tenzro-node tpm provision` \
                     once (add --provision-tpm to let setup do it), then run `tenzro setup` again"
                ));
            }
            wiz_note("Running `tenzro-node tpm provision`...");
            preflight::provision(node)?;
            wiz_done("TPM keys created");
        }
        wiz_gap();
        Ok(())
    }

    /// The network's validator admission, read for this machine's wallet.
    async fn read_admission(&self, _rec: &WizardRecord) -> Admission {
        let rpc_url = self
            .rpc
            .clone()
            .unwrap_or_else(|| "https://rpc.tenzro.com".to_string());
        let account = machine_wallet_account()
            .ok()
            .map(|a| format!("0x{}", hex::encode(a)));
        read_admission(&rpc_url, account.as_deref()).await
    }

    /// Prompt for and validate a machine name.
    ///
    /// Validated as a lowercase DNS label.
    fn resolve_machine_name(&self, interactive: bool) -> Result<String> {
        let default = default_machine_name();
        for attempt in 0..5 {
            let candidate = match (&self.machine_name, attempt) {
                (Some(n), 0) => n.trim().to_ascii_lowercase(),
                _ => prompt_string(interactive, "Machine name", &default)?
                    .trim()
                    .to_ascii_lowercase(),
            };
            match validate_machine_name(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(e) => {
                    if !interactive {
                        return Err(anyhow!("invalid --machine-name '{candidate}': {e}"));
                    }
                    wiz_warn(&e.to_string());
                }
            }
        }
        Err(anyhow!("could not settle on a valid machine name"))
    }

    /// Settle what this node is on the network, returning a real `RoleSet`.
    ///
    /// `--roles` and `--mode` are the script flags: they skip the question and
    /// go through the same requirement gate. Otherwise the user picks a
    /// persona (participant, operator, validator or RPC provider); each line
    /// says what it requires, and one the machine does not meet is refused
    /// with what is unmet and how to fix it, never silently.
    fn resolve_roles(
        &self,
        interactive: bool,
        machine: &MachineFacts,
        admission: &Admission,
    ) -> Result<RoleSet> {
        if let Some(raw) = &self.roles {
            let roles = raw
                .parse::<RoleSet>()
                .map_err(|e| anyhow!("invalid --roles '{raw}': {e}"))?;
            gate_roles(&roles, machine)?;
            gate_admission(&roles, admission)?;
            return Ok(roles);
        }

        // `--mode` is the older, narrower spelling of the same choice.
        if let Some(mode) = self.mode.as_deref() {
            let roles = Persona::from_mode_flag(mode)
                .map(|p| p.roles(&[]))
                .unwrap_or_else(RoleSet::client);
            gate_roles(&roles, machine)?;
            gate_admission(&roles, admission)?;
            wiz_note(&format!("--mode {mode} selected roles: {roles}"));
            return Ok(roles);
        }

        let summary = |p: Persona| match p {
            Persona::Participant => "use the network and its models, light, no serving duties",
            Persona::Operator => "provide AI, compute or storage and earn TNZO",
            Persona::Validator => "take part in consensus",
            Persona::RpcProvider => "serve public RPC",
        };
        for _ in 0..5 {
            let labels: Vec<String> = PERSONAS
                .iter()
                .map(|p| {
                    let gate = persona_availability(*p, machine);
                    let note = match &gate {
                        Ok(()) => String::new(),
                        Err(u) => format!(
                            " [unavailable here: {}]",
                            u.first()
                                .map_or("requirements not met", |u| u.what.as_str())
                        ),
                    };
                    let note = admission_menu_note(*p, admission).unwrap_or(note);
                    format!(
                        "{}: {}; {}{}",
                        p.label(),
                        summary(*p),
                        requirement_line(*p, &[]),
                        note
                    )
                })
                .collect();
            let items: Vec<&str> = labels.iter().map(String::as_str).collect();
            let mut persona = PERSONAS[prompt_select(
                interactive,
                "What do you want to be on the network?",
                &items,
                0,
            )?];

            // Validator admission is closed to this machine: say why, and
            // offer the roles that are open.
            if persona == Persona::Validator && admission.refuses_validator() {
                wiz_warn("This machine cannot be a validator at present.");
                for line in admission_refusal().lines() {
                    wiz_note(line);
                }
                let instead = [Persona::Operator, Persona::Participant];
                let labels: Vec<String> = instead
                    .iter()
                    .map(|p| format!("{}: {}", p.label(), summary(*p)))
                    .collect();
                let items: Vec<&str> = labels.iter().map(String::as_str).collect();
                persona = instead
                    [prompt_select(interactive, "Choose a role that is open now", &items, 1)?];
            }

            if let Err(unmet) = persona_availability(persona, machine) {
                wiz_warn(&format!(
                    "This machine cannot be a {} until these are met:",
                    persona.label().to_ascii_lowercase()
                ));
                for u in &unmet {
                    wiz_note(&format!("{}. Fix: {}.", u.what, u.fix));
                }
                continue;
            }
            if persona != Persona::Operator {
                return Ok(persona.roles(&[]));
            }

            // An operator names what to provide; only services this machine
            // meets are offered.
            let offered: Vec<NetworkRole> = OPERATOR_SERVICES
                .iter()
                .copied()
                .filter(|s| {
                    crate::onboarding::wizard::persona_gate(Persona::Operator, &[*s], machine)
                        .is_ok()
                })
                .collect();
            let names: Vec<&str> = offered
                .iter()
                .map(|s| match s {
                    NetworkRole::ModelProvider => "AI provider: serve models and earn TNZO",
                    NetworkRole::ComputeProvider => "Compute provider: rent out accelerator time",
                    _ => "Storage provider: host network storage",
                })
                .collect();
            let defaults: Vec<bool> = offered.iter().map(|_| false).collect();
            let picked = prompt_multiselect(
                interactive,
                "What will you provide? (space to toggle, enter to confirm)",
                &names,
                &defaults,
            )?;
            let chosen: Vec<NetworkRole> = picked.iter().map(|&i| offered[i]).collect();
            if chosen.is_empty() {
                wiz_note(&format!("Nothing selected; providing {}.", names[0]));
                return Ok(Persona::Operator.roles(&offered[..1]));
            }
            return Ok(Persona::Operator.roles(&chosen));
        }
        Err(anyhow!(
            "no role the machine meets was chosen after five tries. Fix: pick Participant, or fix the unmet requirements above and run `tenzro setup` again."
        ))
    }

    /// Multi-select how provided resources are offered.
    ///
    /// These map onto payment rails the network already speaks: on-demand is
    /// x402 (stateless per-request), subscription is MPP (session-based
    /// streaming), rental is the hourly-bid lease system.
    fn resolve_access_models(&self, interactive: bool) -> Result<Vec<String>> {
        if let Some(raw) = &self.access {
            let picked: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            for a in &picked {
                if !matches!(a.as_str(), "on-demand" | "subscription" | "rental") {
                    return Err(anyhow!(
                        "invalid --access '{a}' (expected on-demand, subscription or rental)"
                    ));
                }
            }
            return Ok(picked);
        }

        let labels = [
            "On-demand — pay per request",
            "Subscription — a metered session over time",
            "Rental — reserve this machine for a fixed term",
        ];
        let keys = ["on-demand", "subscription", "rental"];
        let defaults = [true, false, false];
        let picked = prompt_multiselect(
            interactive,
            "How do you want to offer these resources?",
            &labels,
            &defaults,
        )?;
        let chosen: Vec<String> = picked.iter().map(|&i| keys[i].to_string()).collect();
        Ok(if chosen.is_empty() {
            vec!["on-demand".to_string()]
        } else {
            chosen
        })
    }

    /// Record the wizard's decisions in `~/.tenzro/config.json`.
    fn persist_setup(
        &self,
        display_name: &str,
        machine_name: &str,
        public: bool,
        mode: OperationMode,
        roles: &RoleSet,
        access: &[String],
    ) -> Result<()> {
        // When --data-dir is given, scope config to that directory so an
        // isolated run neither reads nor mutates the global
        // ~/.tenzro/config.json.
        let scoped = self
            .data_dir
            .as_ref()
            .map(tenzro_types::paths::expand_tilde);
        let mut cfg = match &scoped {
            Some(dir) => config::load_config_in(dir),
            None => config::load_config(),
        };
        cfg.display_name = Some(display_name.to_string());
        cfg.machine_name = Some(machine_name.to_string());
        cfg.public = Some(public);
        cfg.operator_mode = Some(mode.slug().to_string());
        cfg.roles = Some(roles.to_string());
        if !access.is_empty() {
            cfg.access_models = Some(access.join(","));
        }
        // Record the endpoint this setup actually used. This is the public
        // network path, so absent an explicit `--rpc` that is the public
        // network — not loopback. A validator overwrites this with its own
        // local node afterwards in `run_public_validator`, which is correct
        // there because a validator runs the node it talks to; the local and
        // private paths do the same for the same reason.
        if cfg.endpoint.is_none() {
            cfg.endpoint = Some(
                self.rpc
                    .clone()
                    .unwrap_or_else(|| "https://rpc.tenzro.com".to_string()),
            );
        }
        match &scoped {
            Some(dir) => config::save_config_in(dir, &cfg),
            None => config::save_config(&cfg),
        }
    }

    async fn run_public_validator(
        &self,
        interactive: bool,
        name: &str,
        hw: &HardwareProfile,
    ) -> Result<()> {
        wiz_section("Validator setup");
        self.run_preflight(interactive, hw)?;

        let default_dir = tenzro_types::paths::default_data_dir();
        let data_dir = match &self.data_dir {
            Some(d) => tenzro_types::paths::expand_tilde(d),
            // A tilde typed at a prompt was never seen by a shell, so nothing
            // has expanded it; taken literally it creates a directory named
            // `~` in the current folder.
            None => tenzro_types::paths::expand_tilde(prompt_string(
                interactive,
                "Node data directory",
                &default_dir.display().to_string(),
            )?),
        };

        let pubkeys = validator_pubkeys(&data_dir)?;
        let account = format!("0x{}", hex::encode(machine_wallet_account()?));
        let rpc_url = self
            .rpc
            .clone()
            .unwrap_or_else(|| "https://rpc.tenzro.com".to_string());
        let (balance, governed) = read_validator_chain_facts(&rpc_url, &account).await;
        // The node refuses to register below the governed minimum, so a
        // self-stake under it would leave the validator unregistered without
        // saying why.
        let stake_wei = governed.map_or(self.validator_stake, |g| g.max(self.validator_stake));
        wiz_gap();
        wiz_kv("Data directory", &data_dir.display().to_string());
        wiz_kv(
            "Validator pubkey",
            &format!("0x{}", hex::encode(&pubkeys.ed25519)),
        );
        wiz_kv("Validator account", &account);
        wiz_kv(
            "Self-stake",
            &format!(
                "{} (registered by the node itself)",
                crate::rpc::format_tnzo(stake_wei)
            ),
        );

        // The node registers itself on boot with its own hardware keys when
        // the unit carries `--validator-self-stake`; nothing is pasted by hand.
        let extra = ["--validator-self-stake".to_string(), stake_wei.to_string()];
        let unit_path = write_service_unit(&data_dir, None, None, "validator", &extra)?;

        let need = StakeNeed {
            role: "validator".to_string(),
            required_wei: stake_wei + VALIDATOR_GAS_RESERVE_WEI,
            balance_wei: balance,
            account: account.clone(),
        };
        if !need.is_met()
            && crate::onboarding::phase::Phase::current()
                == crate::onboarding::phase::Phase::Foundation
        {
            // Where the application stands, so the screen below continues
            // from there instead of starting over. Kept in the CLI config.
            let _ = crate::onboarding::flow::snapshot(
                &crate::rpc::RpcClient::new(&rpc_url),
                &crate::onboarding::flow::AnySource::from_env(),
                crate::onboarding::role::JoinRole::Validator.slug(),
                Some(crate::onboarding::role::JoinRole::Validator),
                &account,
                need.required_wei,
            )
            .await;
        }
        if need.is_met() {
            stake_options::forget()?;
        } else {
            wiz_section("Stake");
            need.render(|kind, text| match kind {
                LineKind::Heading => wiz_warn(&text),
                LineKind::Text => wiz_note(&text),
                LineKind::Command => wiz_cmd(&[text]),
            });
            need.remember()?;
        }

        wiz_section("Next steps");
        for step in validator_next_steps(&data_dir, &unit_path, &account, stake_wei, need.is_met())
        {
            wiz_note(&step.text);
            if !step.commands.is_empty() {
                wiz_cmd(&step.commands);
            }
        }

        let mut cfg = config::load_config();
        cfg.endpoint = Some("http://127.0.0.1:8545".to_string());
        cfg.display_name = Some(name.to_string());
        cfg.roles = Some("validator".to_string());
        config::save_config(&cfg)?;
        if self.wants_apply(interactive)? {
            self.apply_service(interactive, hw, &unit_path, true)
                .await?;
        }
        wiz_outro("Setup complete: the node registers itself once the account is funded");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Path 2 — local / sovereign network bootstrap
    // ------------------------------------------------------------------

    async fn run_local_path(&self, interactive: bool, hw: &HardwareProfile) -> Result<()> {
        wiz_section("Local network setup");
        if self.apply {
            return Err(anyhow!(
                "--apply does not apply to a new network: its genesis lists no founding validators \
                 until each one prints its entry with `tenzro-node validator-entry`. Finish the \
                 genesis, then start the node as printed below."
            ));
        }
        self.run_preflight(interactive, hw)?;

        let network_name = match &self.network_name {
            Some(n) => n.clone(),
            None => prompt_string(interactive, "Network name", "local")?,
        };

        let base = tenzro_types::paths::network_dir(&network_name);
        let data_dir = self
            .data_dir
            .as_ref()
            .map(tenzro_types::paths::expand_tilde)
            .unwrap_or_else(|| base.join("data"));

        let chain_id = match self.chain_id {
            Some(id) => id,
            None => {
                let suggested: u64 = rand::thread_rng().gen_range(10_000..100_000);
                if interactive {
                    prompt_string(interactive, "Chain id", &suggested.to_string())?
                        .trim()
                        .parse::<u64>()
                        .map_err(|e| anyhow!("invalid chain id: {}", e))?
                } else {
                    suggested
                }
            }
        };

        // Consensus keys keep their sealed design; this only makes sure they exist.
        validator_pubkeys(&data_dir)?;
        let identity = machine_identity()?;

        std::fs::create_dir_all(&base).map_err(|e| anyhow!("create {}: {}", base.display(), e))?;

        let genesis_path = base.join("genesis.toml");
        if genesis_path.exists() {
            wiz_warn(&format!(
                "Genesis already exists at {} — keeping it",
                genesis_path.display()
            ));
        } else {
            // The founder account is this machine's hardware wallet key, never
            // a key derived for consensus.
            let founder_address = hex::encode(machine_wallet_account()?);
            let mut g = String::new();
            g.push_str(&format!(
                "version = {}\nchain_id = {}\ntimestamp = 0\n\n",
                tenzro_types::constants::GENESIS_SCHEMA_VERSION,
                chain_id
            ));
            g.push_str(&format!(
                "# founding validators: append each one's entry, printed on its own machine by\n\
                 #   tenzro-node validator-entry --data-dir <dir> --stake {}\n",
                self.stake
            ));
            g.push_str("\n[[accounts]]\n");
            g.push_str(&format!("address = \"{}\"\n", founder_address));
            g.push_str("balance = 1000000\n");
            std::fs::write(&genesis_path, g)
                .map_err(|e| anyhow!("write {}: {}", genesis_path.display(), e))?;
            wiz_done(&format!("Genesis written to {}", genesis_path.display()));
        }

        let unit_path =
            write_service_unit(&data_dir, Some(&genesis_path), None, "validator,ai", &[])?;

        wiz_gap();
        wiz_kv("Network", &network_name);
        wiz_kv("Chain id", &chain_id.to_string());
        wiz_kv("Data directory", &data_dir.display().to_string());
        wiz_kv("Machine identity", &identity);

        wiz_section("Start your network");
        wiz_note(
            "On this machine (founding validator), serving the relay role so peers need no inbound port:",
        );
        wiz_cmd(&[
            format!(
                "tenzro-node --roles validator,ai --data-dir {} --genesis {} \\",
                data_dir.display(),
                genesis_path.display()
            ),
            "  --relay-listen 127.0.0.1:3340 --relay-url <the https URL your edge serves it at>"
                .to_string(),
        ]);
        wiz_note("To add a peer, copy the genesis file to it:");
        wiz_cmd(&[format!(
            "scp {} <peer>:~/.tenzro/networks/{}/genesis.toml",
            genesis_path.display(),
            network_name
        )]);
        wiz_note("Then on the peer:");
        wiz_cmd(&[
            "tenzro-node --roles ai \\".to_string(),
            format!(
                "  --genesis ~/.tenzro/networks/{}/genesis.toml \\",
                network_name
            ),
            format!("  --data-dir ~/.tenzro/networks/{}/data \\", network_name),
            format!("  --boot-nodes {identity}@<relay url>"),
        ]);
        wiz_note(
            "When another peer serves a relay too, list it as well, comma separated \
             (<id>@<relay url>,<id>@<relay url>): the peer then keeps its connections when one relay stops.",
        );
        wiz_note("Optional: run the node as a service.");
        wiz_note(&format!(
            "A unit file was written to {}",
            unit_path.display()
        ));

        let mut cfg = config::load_config();
        cfg.endpoint = Some("http://127.0.0.1:8545".to_string());
        cfg.roles = Some("validator".to_string());
        config::save_config(&cfg)?;
        wiz_outro("Setup complete — configuration saved");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Path 3 — join an existing private network
    // ------------------------------------------------------------------

    async fn run_private_path(&self, interactive: bool, hw: &HardwareProfile) -> Result<()> {
        wiz_section("Private network join");

        let genesis = match &self.genesis {
            Some(g) => g.clone(),
            None if interactive => PathBuf::from(prompt_string(
                interactive,
                "Path to the network's genesis.toml",
                "",
            )?),
            None => {
                return Err(anyhow!(
                    "--genesis is required in non-interactive mode (path to the network's genesis.toml)"
                ));
            }
        };
        if !genesis.exists() {
            wiz_warn(&format!(
                "{} does not exist: copy it from the network operator before starting the node",
                genesis.display()
            ));
        }

        let bootstrap = match &self.bootstrap {
            Some(b) => b.clone(),
            None if interactive => prompt_string(
                interactive,
                "Boot identity (did:tenzro:machine:<id>@<relay url>, from the network operator)",
                "",
            )?,
            None => {
                return Err(anyhow!(
                    "--bootstrap is required in non-interactive mode (the boot identity of an existing node)"
                ));
            }
        };
        if !bootstrap.trim().starts_with("did:tenzro:machine:") {
            return Err(anyhow!(
                "a boot identity (did:tenzro:machine:<id>@<relay url>) is required to join a private \
                 network; network addresses are not accepted"
            ));
        }

        let default_dir = tenzro_types::paths::default_data_dir();
        let data_dir = match &self.data_dir {
            Some(d) => tenzro_types::paths::expand_tilde(d),
            // A tilde typed at a prompt was never seen by a shell, so nothing
            // has expanded it; taken literally it creates a directory named
            // `~` in the current folder.
            None => tenzro_types::paths::expand_tilde(prompt_string(
                interactive,
                "Node data directory",
                &default_dir.display().to_string(),
            )?),
        };

        let items = [
            "Provide models and compute (ai)",
            "Validator (requires the operator to include your keys in genesis or admit your stake)",
        ];
        let roles = match prompt_select(interactive, "Role on this network", &items, 0)? {
            1 => "validator,ai",
            _ => "ai",
        };

        // Every role on a private network keeps its node's keys in hardware,
        // so the preflight runs whatever the role: no unit is written for a
        // machine that cannot hold the identity key.
        self.run_preflight(interactive, hw)?;
        if roles.starts_with("validator") {
            // Refuses here, before anything is written, on a machine whose
            // hardware cannot derive the keys.
            validator_pubkeys(&data_dir)?;
            wiz_gap();
            wiz_note("Send the network operator this machine's genesis entry, printed by:");
            wiz_cmd(&[format!(
                "tenzro-node validator-entry --data-dir {} --stake {}",
                data_dir.display(),
                self.stake
            )]);
        }

        let unit_path =
            write_service_unit(&data_dir, Some(&genesis), Some(&bootstrap), roles, &[])?;

        wiz_section("Start your node");
        wiz_cmd(&[
            format!("tenzro-node --roles {} \\", roles),
            format!("  --data-dir {} \\", data_dir.display()),
            format!("  --genesis {} \\", genesis.display()),
            format!("  --boot-nodes {}", bootstrap),
        ]);
        wiz_note("Optional: run the node as a service.");
        wiz_note(&format!(
            "A unit file was written to {}",
            unit_path.display()
        ));

        let mut cfg = config::load_config();
        cfg.endpoint = Some("http://127.0.0.1:8545".to_string());
        cfg.roles = Some(roles.to_string());
        config::save_config(&cfg)?;
        if self.wants_apply(interactive)? {
            self.apply_service(interactive, hw, &unit_path, true)
                .await?;
        }
        wiz_outro("Setup complete — configuration saved");
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// Why a scoped autonomous setup run needs `--rpc`.
pub const SCOPED_IDENTITY_NEEDS_RPC: &str = "this setup run is scoped to a data directory (--data-dir or \
     $TENZRO_DATA_DIR) and the identity step cannot be skipped: pass --rpc <the node to register this \
     machine on>. There is no way to set up a participant without its hardware-rooted identity.";

/// The node the autonomous identity step registers on. The public network
/// path reaches the public network, the same endpoint `JoinCmd` resolves to
/// for a non-provider join; defaulting to loopback would register against a
/// node that need not exist. A scoped run (an explicit data directory, which
/// `$TENZRO_DATA_DIR` also sets) must not register against the live network
/// by accident, so it names its node; it can not skip the step.
fn autonomous_identity_rpc(rpc: Option<&str>, scoped: bool) -> Result<String> {
    match (rpc, scoped) {
        (Some(url), _) => Ok(url.to_string()),
        (None, false) => Ok("https://rpc.tenzro.com".to_string()),
        (None, true) => Err(anyhow!(SCOPED_IDENTITY_NEEDS_RPC)),
    }
}

/// One numbered step the wizard prints: a sentence and, optionally, the
/// commands that carry it out.
pub struct NextStep {
    pub text: String,
    pub commands: Vec<String>,
}

/// The steps that follow a public-network validator setup, in order. Every
/// `tenzro ...` command in them is a real subcommand; a test in the CLI binary
/// parses each one with the CLI's own parser.
pub fn validator_next_steps(
    data_dir: &Path,
    unit_path: &Path,
    account: &str,
    stake_wei: u128,
    funded: bool,
) -> Vec<NextStep> {
    let stake = crate::rpc::format_tnzo(stake_wei);
    vec![
        NextStep {
            text: if funded {
                format!("1. The validator account holds the {stake} self-stake and gas.")
            } else {
                format!(
                    "1. Fund the validator account with {stake} for the self-stake plus gas, by one \
                     of the options above, at:"
                )
            },
            commands: if funded {
                Vec::new()
            } else {
                vec![account.to_string()]
            },
        },
        NextStep {
            text: "2. Start the node. With the account funded it registers itself as a validator \
                   on boot; unfunded, it starts and skips registration until it is restarted:"
                .to_string(),
            commands: vec![format!(
                "tenzro-node --roles validator --data-dir {} --validator-self-stake {}",
                data_dir.display(),
                stake_wei
            )],
        },
        NextStep {
            text: format!(
                "   Or run it as a service (a unit was written to {}):",
                unit_path.display()
            ),
            commands: vec![
                format!(
                    "sudo cp {} /etc/systemd/system/tenzro-node.service",
                    unit_path.display()
                ),
                "sudo systemctl enable --now tenzro-node".to_string(),
            ],
        },
        NextStep {
            text: "3. Confirm the registration. The validator is admitted to the active set at \
                   the next epoch boundary:"
                .to_string(),
            commands: vec![format!("tenzro validator get {account}")],
        },
    ]
}

/// The `tenzro ...` commands in `steps`, one per line, for the CLI's
/// parse-every-printed-command test.
pub fn printed_tenzro_commands(steps: &[NextStep]) -> Vec<String> {
    steps
        .iter()
        .flat_map(|s| s.commands.iter())
        .filter(|c| c.starts_with("tenzro "))
        .cloned()
        .collect()
}

/// The RPC address a node started by `tenzro setup` listens on.
const LOCAL_RPC: &str = "http://127.0.0.1:8545";

/// What the network says about validator admission, for this machine's
/// account when it can be read. A read that fails is [`Admission::Unknown`].
pub(crate) async fn read_admission(rpc_url: &str, account: Option<&str>) -> Admission {
    crate::rpc::RpcClient::new(rpc_url)
        .call::<serde_json::Value>(
            "tenzro_getNetworkParams",
            serde_json::json!({ "validator_admission": true, "address": account }),
        )
        .await
        .map_or(Admission::Unknown, |v| Admission::from_reply(&v))
}

/// TNZO kept above the self-stake for the registration transaction's gas.
const VALIDATOR_GAS_RESERVE_WEI: u128 = tenzro_types::constants::ONE_TNZO;

/// The validator account's balance and the governed validator stake, in wei,
/// read from the node at `rpc_url`. A read that fails is `None`.
async fn read_validator_chain_facts(rpc_url: &str, account: &str) -> (Option<u128>, Option<u128>) {
    let rpc = crate::rpc::RpcClient::new(rpc_url);
    let balance = rpc
        .call::<serde_json::Value>("eth_getBalance", serde_json::json!([account, "latest"]))
        .await
        .ok()
        .and_then(|v| {
            v.as_str()
                .and_then(|h| u128::from_str_radix(h.trim_start_matches("0x"), 16).ok())
        });
    let governed = rpc
        .call::<serde_json::Value>(
            "tenzro_getNetworkParams",
            serde_json::json!({ "key": "stake.validator_tnzo" }),
        )
        .await
        .ok()
        .and_then(|v| {
            v.get("value")
                .and_then(|x| x.as_str())
                .and_then(|x| x.parse::<u128>().ok())
        })
        .map(|tnzo| tnzo * tenzro_types::constants::ONE_TNZO);
    (balance, governed)
}

fn print_hardware_summary(hw: &HardwareProfile) {
    wiz_kv(
        "CPU",
        &format!(
            "{} ({} cores / {} threads)",
            hw.cpu_model, hw.cpu_cores, hw.cpu_threads
        ),
    );
    wiz_kv(
        "Memory",
        &format!(
            "{:.0} GB{}",
            hw.total_ram_gb,
            if hw.unified_memory { " (unified)" } else { "" }
        ),
    );
    if hw.gpus.is_empty() {
        wiz_kv("GPU", "none detected");
    } else {
        for gpu in &hw.gpus {
            wiz_kv("GPU", &format!("{} ({:.0} GB)", gpu.name, gpu.memory_gb));
        }
    }
    wiz_kv(
        "Storage available",
        &format!("{:.0} GB", hw.storage_available_gb),
    );
    wiz_kv(
        "TEE",
        &hw.tee_type
            .clone()
            .unwrap_or_else(|| "not available".to_string()),
    );
}

fn prompt_string(interactive: bool, prompt: &str, default: &str) -> Result<String> {
    if interactive {
        let theme = wizard_theme();
        let mut input = Input::<String>::with_theme(&theme).with_prompt(prompt);
        if !default.is_empty() {
            input = input.default(default.to_string());
        }
        Ok(input.interact_text()?)
    } else {
        Ok(default.to_string())
    }
}

/// The wallet balance in wei, `None` when the node cannot be asked.
async fn read_balance(rpc_url: &str, account: &str) -> Option<u128> {
    let v = crate::rpc::RpcClient::new(rpc_url)
        .call::<serde_json::Value>("eth_getBalance", serde_json::json!([account, "latest"]))
        .await
        .ok()?;
    crate::onboarding::flow::parse_balance(&v)
}

/// Whether this machine can anchor an identity without a human, and why not
/// when it cannot.
///
/// Checked locally rather than over RPC on purpose: the wizard runs *before*
/// a node exists, so an RPC-based eligibility probe would have nothing to ask.
struct MachineAnchorOptions {
    autonomous_available: bool,
    reason: String,
}

impl MachineAnchorOptions {
    fn detect(hw: &HardwareProfile) -> Self {
        // On Apple hardware the machine root is the Secure Enclave, not a TPM.
        // Sealing goes through the SEP-bound machine root (no external tooling),
        // so a usable Secure Enclave is a complete autonomous anchor on its own.
        if has_secure_enclave(hw) {
            return Self {
                autonomous_available: true,
                reason: String::new(),
            };
        }

        // `tpm_available` in the hardware profile means only that a TPM
        // device node exists. Sealing also shells out to tpm2-tools, so a
        // machine with the chip but not the tooling would pass a naive check
        // and then fail at the point of actually sealing a key — after the
        // operator had already committed to autonomous operation.
        let has_device = hw
            .tee_capabilities
            .iter()
            .any(|c| c == "tpm_available" || c == "tpm_enabled");
        if !has_device {
            return Self {
                autonomous_available: false,
                reason: if cfg!(target_os = "macos") {
                    "no usable Secure Enclave detected on this Mac".to_string()
                } else {
                    "no TPM detected on this machine".to_string()
                },
            };
        }

        const TPM_TOOLS: &[&str] = &[
            "tpm2_create",
            "tpm2_createprimary",
            "tpm2_load",
            "tpm2_unseal",
        ];
        let missing: Vec<&str> = TPM_TOOLS
            .iter()
            .copied()
            .filter(|t| which_on_path(t).is_none())
            .collect();
        if !missing.is_empty() {
            return Self {
                autonomous_available: false,
                reason: format!(
                    "TPM present but tpm2-tools missing ({}) — install tpm2-tools to enable",
                    missing.join(", ")
                ),
            };
        }

        Self {
            autonomous_available: true,
            reason: String::new(),
        }
    }
}

/// Whether this is Apple hardware with a live Secure Enclave, from the
/// capabilities `hardware.rs` records for it.
pub(crate) fn has_secure_enclave(hw: &HardwareProfile) -> bool {
    hw.tee_capabilities
        .iter()
        .any(|c| c == "secure_key_storage" || c == "hardware_attestation")
        && cfg!(any(target_os = "macos", target_os = "ios"))
}

/// Minimal `which`, so the CLI need not depend on `tenzro-tee` (whose TPM
/// surface is a node-side concern) just to test for a binary.
pub(crate) fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    // On Windows a program is `name.exe`: try the bare name, then with the suffix.
    let with_suffix = format!("{bin}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&path).find_map(|dir| {
        [bin, with_suffix.as_str()].into_iter().find_map(|n| {
            let candidate = dir.join(n);
            candidate.is_file().then_some(candidate)
        })
    })
}

/// Whether `name` is a legal machine name: 3 to 63 characters of
/// `[a-z0-9-]`, not starting or ending with a hyphen.
fn validate_machine_name(name: &str) -> std::result::Result<(), String> {
    if name.len() < 3 {
        return Err("machine name must be at least 3 characters".into());
    }
    if name.len() > 63 {
        return Err("machine name must be at most 63 characters".into());
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(format!(
            "machine name may only contain lowercase letters, digits and hyphens (found {c:?})"
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("machine name must not start or end with a hyphen".into());
    }
    Ok(())
}

/// A machine name suggestion derived from the host's own name.
///
/// Only a suggestion — sanitised into a legal DNS label, and falling back to
/// a generic stem when the hostname yields nothing usable.
fn default_machine_name() -> String {
    let raw = hostname_lossy().unwrap_or_default();
    let cleaned: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if validate_machine_name(&cleaned).is_ok() {
        cleaned
    } else {
        "tenzro-node".to_string()
    }
}

/// This machine's name for the full-screen setup's defaults.
pub(crate) fn hostname_for_tui() -> String {
    hostname_lossy().unwrap_or_else(|| "tenzro".to_string())
}

fn hostname_lossy() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
}

/// Multi-select prompt. Non-interactive runs take `defaults` verbatim, so
/// `--yes` produces exactly what the flags say.
fn prompt_multiselect(
    interactive: bool,
    prompt: &str,
    items: &[&str],
    defaults: &[bool],
) -> Result<Vec<usize>> {
    if interactive {
        Ok(MultiSelect::with_theme(&wizard_theme())
            .with_prompt(prompt)
            .items(items)
            .defaults(defaults)
            .interact()?)
    } else {
        Ok(defaults
            .iter()
            .enumerate()
            .filter_map(|(i, on)| on.then_some(i))
            .collect())
    }
}

/// Yes/no prompt, answered with the enter key's default.
fn prompt_confirm(prompt: &str, default: bool) -> Result<bool> {
    Ok(dialoguer::Confirm::with_theme(&wizard_theme())
        .with_prompt(prompt)
        .default(default)
        .interact()?)
}

fn prompt_select(interactive: bool, prompt: &str, items: &[&str], default: usize) -> Result<usize> {
    if interactive {
        Ok(Select::with_theme(&wizard_theme())
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .interact()?)
    } else {
        Ok(default)
    }
}

/// This machine's validator public keys, derived from its TPM or Secure
/// Enclave. Nothing is generated or written: reruns of the wizard see the
/// same identity because the same hardware derives the same keys.
fn validator_pubkeys(data_dir: &Path) -> Result<tenzro_keygen::ValidatorPubkeys> {
    let pubkeys = tenzro_keygen::NodeKeys::open(data_dir)?.validator_pubkeys()?;
    wiz_done("Validator keys derived from this machine's hardware (Ed25519 + ML-DSA-65)");
    Ok(pubkeys)
}

/// This machine's identity, `did:tenzro:machine:<id>`, derived from its
/// hardware identity key. Peers join the network by it.
/// The ledger account of this machine's hardware wallet key (TPM or Secure
/// Enclave P-256).
fn machine_wallet_account() -> Result<[u8; 32]> {
    use tenzro_crypto::HybridSigner as _;
    let signer = tenzro_device_key::HardwareHybridSigner::open_or_create(
        tenzro_types::did_derivation::MACHINE_WALLET_KEY_LABEL,
    )
    .map_err(|e| anyhow!("this machine's wallet key: {}", e))?;
    Ok(tenzro_crypto::composite::account_slot(
        &signer.public_key().p256,
    ))
}

fn machine_identity() -> Result<String> {
    let key =
        tenzro_device_key::signer::open_or_create(tenzro_types::did_derivation::MACHINE_KEY_LABEL)
            .map_err(|e| anyhow!("this machine's identity key: {}", e))?;
    let public_key = key
        .public_key_sec1()
        .map_err(|e| anyhow!("this machine's identity key: {}", e))?;
    Ok(tenzro_types::did_derivation::machine_did(&public_key))
}

/// The `tenzro-node` binary this CLI would run: a sibling of the current
/// executable, else the first one on PATH.
pub(crate) fn locate_node_binary() -> Option<PathBuf> {
    let node_name = format!("tenzro-node{}", std::env::consts::EXE_SUFFIX);
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(&node_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    which_on_path(&node_name)
}

/// The paths a service unit names.
struct ServicePaths {
    /// The node the service starts.
    node: String,
    /// The `tenzro` that counts each start against an open update trial.
    tenzro: String,
    /// The install directory an update changes.
    install_dir: String,
}

/// The service paths for the `tenzro` at `exe`.
///
/// In a versioned install they go through the `current` link, never through
/// the release directory `exe` resolves to: an update repoints `current` and
/// later removes old release directories, and the service has to start
/// whichever release is current. The node is the one installed beside this
/// `tenzro`; when none is there, the usual install location is named, since
/// launchd needs an absolute path.
fn service_paths_for(exe: &Path) -> ServicePaths {
    let node_name = format!("tenzro-node{}", std::env::consts::EXE_SUFFIX);
    let cli_name = format!("tenzro{}", std::env::consts::EXE_SUFFIX);
    let layout = Layout::of_executable(exe).unwrap_or_else(|_| Layout::Flat {
        dir: exe.parent().map(Path::to_path_buf).unwrap_or_default(),
    });
    let tenzro = match &layout {
        Layout::Versioned { .. } => layout.binary(&cli_name),
        Layout::Flat { .. } => exe.to_path_buf(),
    };
    let node = Some(layout.binary(&node_name))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/tenzro-node"));
    ServicePaths {
        node: node.display().to_string(),
        tenzro: tenzro.display().to_string(),
        install_dir: layout.dir().display().to_string(),
    }
}

/// The service paths for the `tenzro` that is running.
fn service_paths() -> ServicePaths {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/tenzro"));
    service_paths_for(&exe)
}

/// The unprivileged account the generated unit runs the node as: the user
/// running the wizard. A node never runs as root.
fn service_user() -> Result<String> {
    match std::env::var("USER") {
        Ok(u) if !u.is_empty() && u != "root" => Ok(u),
        _ => Err(anyhow!(
            "run the setup wizard as the unprivileged account the node will run as, not root"
        )),
    }
}

/// The resource-control lines of the node's systemd unit, by role. A
/// validator is the last thing the kernel may kill and the first to get CPU
/// and disk time; its memory is capped as a share of the machine (systemd
/// reads the percentages against physical memory), so the cap fits whatever
/// host it runs on. A node that also serves models on this machine gets no
/// memory cap: its model memory is charged outside the cgroup on
/// unified-memory hardware, where a cap would bound the wrong thing.
fn hardening_block(roles: &str) -> String {
    let has = |r: &str| roles.split(',').any(|x| x.trim() == r);
    let validator = has("validator");
    let serves_models = has("ai") || has("provider") || has("model-provider");
    let mut out = String::new();
    out.push_str(
        "\n# Load protection. The unit sets the node's place among the services of the\n\
         # machine: who the kernel kills last, who gets CPU and disk first, and how\n\
         # many threads it may start. The node sheds its own load by priority; see\n\
         # docs/LOAD-PROTECTION.md.\n",
    );
    if validator {
        out.push_str("OOMScoreAdjust=-900\nCPUWeight=800\nIOWeight=800\nNice=-5\nTasksMax=16384\n");
        out.push_str("MemoryLow=1G\n");
        if !serves_models {
            // Swap is a cliff for a consensus process: when it is used up the
            // machine thrashes. The cap throttles at three quarters and kills
            // at seven eighths, never swaps.
            out.push_str("MemoryHigh=75%\nMemoryMax=88%\nMemorySwapMax=0\n");
        }
    } else {
        out.push_str("OOMScoreAdjust=-200\nCPUWeight=200\nIOWeight=200\nTasksMax=16384\n");
    }
    out
}

/// Write a launchd plist (macOS) or systemd unit (Linux) into `data_dir`
/// with install instructions in the file header.
fn write_service_unit(
    data_dir: &Path,
    genesis: Option<&Path>,
    bootstrap: Option<&str>,
    roles: &str,
    extra_args: &[String],
) -> Result<PathBuf> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| anyhow!("create {}: {}", data_dir.display(), e))?;

    let paths = service_paths();
    let mut args = vec![
        "--roles".to_string(),
        roles.to_string(),
        "--data-dir".to_string(),
        data_dir.display().to_string(),
    ];
    if let Some(g) = genesis {
        args.push("--genesis".to_string());
        args.push(g.display().to_string());
    }
    if let Some(b) = bootstrap {
        args.push("--boot-nodes".to_string());
        args.push(b.to_string());
    }
    args.extend(extra_args.iter().cloned());

    let (name, content) = if std::env::consts::OS == "macos" {
        (
            "network.tenzro.node.plist",
            launchd_plist_text(data_dir, &paths, &args),
        )
    } else {
        (
            "tenzro-node.service",
            systemd_unit_text(data_dir, &paths, &args, roles, &service_user()?),
        )
    };
    let path = data_dir.join(name);
    std::fs::write(&path, content).map_err(|e| anyhow!("write {}: {}", path.display(), e))?;
    Ok(path)
}

/// The launchd agent `tenzro setup` writes on macOS, with install
/// instructions in its header. Pure.
fn launchd_plist_text(data_dir: &Path, paths: &ServicePaths, args: &[String]) -> String {
    let plist_args = service::launchd_arguments(
        &paths.tenzro,
        &paths.install_dir,
        &data_dir.display().to_string(),
        &paths.node,
        args,
    )
    .iter()
    .map(|a| format!("        <string>{}</string>", service::xml_escape(a)))
    .collect::<Vec<_>>()
    .join("\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Install:
       cp {plist} ~/Library/LaunchAgents/network.tenzro.node.plist
       launchctl load ~/Library/LaunchAgents/network.tenzro.node.plist -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>network.tenzro.node</string>
    <!-- Counts this start against an open update trial, then starts the
         node. A count that fails never holds the node back. -->
    <key>ProgramArguments</key>
    <array>
{plist_args}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{data_dir}/node.log</string>
    <key>StandardErrorPath</key>
    <string>{data_dir}/node.log</string>
</dict>
</plist>
"#,
        plist = data_dir.join("network.tenzro.node.plist").display(),
        plist_args = plist_args,
        data_dir = data_dir.display(),
    )
}

/// The systemd unit `tenzro setup` writes on Linux, with install instructions
/// in its header. Pure.
fn systemd_unit_text(
    data_dir: &Path,
    paths: &ServicePaths,
    args: &[String],
    roles: &str,
    user: &str,
) -> String {
    let exec = format!("{} {}", paths.node, args.join(" "));
    let boot_check = format!(
        "{} update boot-check --install-dir {} --data-dir {}",
        paths.tenzro,
        paths.install_dir,
        data_dir.display()
    );
    format!(
        r#"# Install:
#   sudo cp {unit} /etc/systemd/system/tenzro-node.service
#   sudo systemctl enable --now tenzro-node
[Unit]
Description=Tenzro node
After=network-online.target
Wants=network-online.target

[Service]
# Confined: the invoking unprivileged user, no new privileges, a read-only
# system, writable data directory only, and only the TPM and GPU devices.
# Every HTTP listener binds loopback; public exposure is the operator's own
# proxy, outside the node.
User={user}
# Counts this start against an open update trial. The leading "-" means a
# count that fails never holds the node back.
ExecStartPre=-{boot_check}
ExecStart={exec}
NoNewPrivileges=true
CapabilityBoundingSet=
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={data_dir}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
DeviceAllow=char-nvidiactl rw
DeviceAllow=char-nvidia-uvm rw
DeviceAllow=char-nvidia-frontend rw
DeviceAllow=char-drm rw
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillSignal=SIGTERM

# RocksDB opens many files and a node holds a socket per peer. The default soft
# limit of 1024 is not enough, and the failure surfaces as an obscure "Too many
# open files" from the storage engine rather than as anything naming the limit.
LimitNOFILE=65536

# A floor, not a cap. See the packaged unit for why a cgroup MemoryMax is the
# wrong instrument here: on unified-memory hardware the allocations that consume
# the pool are not charged to this cgroup, so a cap would bound the bookkeeping
# and not the memory. The node's own [memory] budget is the ceiling.
MemoryMin=1G
{hardening}
[Install]
WantedBy=multi-user.target
"#,
        unit = data_dir.join("tenzro-node.service").display(),
        hardening = hardening_block(roles),
        boot_check = boot_check,
        exec = exec,
        user = user,
        data_dir = data_dir.display(),
    )
}

// ----------------------------------------------------------------------
// Wizard presentation
// ----------------------------------------------------------------------
//
// The wizard renders as one continuous flow: a rounded welcome box, then
// a vertical rail — `◇` marks a completed step, `◆` (via the dialoguer
// theme) marks the active prompt, `└` closes the run. Colors degrade
// automatically when stdout is not a terminal.

/// Inner width of the welcome box, excluding the border characters.
const BANNER_INNER_WIDTH: usize = 56;

fn wiz_box_line(plain: &str, styled: &str) {
    let pad = BANNER_INNER_WIDTH.saturating_sub(plain.chars().count() + 2);
    println!(
        "{}  {}{}{}",
        style("│").dim(),
        styled,
        " ".repeat(pad),
        style("│").dim()
    );
}

fn wiz_intro() {
    println!();
    println!(
        "{}",
        style(format!("╭{}╮", "─".repeat(BANNER_INNER_WIDTH))).dim()
    );
    wiz_box_line("", "");
    wiz_box_line(
        "Tenzro Setup",
        &style("Tenzro Setup").cyan().bold().to_string(),
    );
    wiz_box_line(
        "Join, provide, validate, or bootstrap a network",
        &style("Join, provide, validate, or bootstrap a network")
            .dim()
            .to_string(),
    );
    wiz_box_line("", "");
    println!(
        "{}",
        style(format!("╰{}╯", "─".repeat(BANNER_INNER_WIDTH))).dim()
    );
}

/// A bare rail connector line.
fn wiz_gap() {
    println!("{}", style("│").dim());
}

/// A completed-step section header on the rail.
fn wiz_section(title: &str) {
    wiz_gap();
    println!("{}  {}", style("◇").green(), style(title).bold());
}

/// A key/value detail line on the rail.
fn wiz_kv(key: &str, value: &str) {
    println!(
        "{}    {} {}",
        style("│").dim(),
        style(format!("{:<18}", key)).dim(),
        value
    );
}

/// A plain instruction line on the rail.
fn wiz_note(msg: &str) {
    println!("{}  {}", style("│").dim(), msg);
}

/// A warning line on the rail.
fn wiz_warn(msg: &str) {
    println!("{}  {}", style("▲").yellow(), msg);
}

/// A completed-action line on the rail.
fn wiz_done(msg: &str) {
    println!("{}  {}", style("◇").green(), msg);
}

/// A command block on the rail, one line per element.
fn wiz_cmd(lines: &[String]) {
    wiz_gap();
    for line in lines {
        println!("{}      {}", style("│").dim(), style(line).cyan());
    }
    wiz_gap();
}

/// The closing line of the wizard run.
fn wiz_outro(msg: &str) {
    wiz_gap();
    println!("{}  {}", style("└").dim(), style(msg).green().bold());
    println!();
}

/// dialoguer theme matched to the wizard rail: `◆` on the active prompt,
/// `◇` once answered, `❯` on the highlighted item, dim hints. dialoguer
/// renders to stderr, hence `for_stderr` on every style.
fn wizard_theme() -> ColorfulTheme {
    ColorfulTheme {
        prompt_prefix: style("◆".to_string()).for_stderr().color256(110),
        success_prefix: style("◇".to_string()).for_stderr().green(),
        error_prefix: style("▲".to_string()).for_stderr().red(),
        active_item_prefix: style("❯".to_string()).for_stderr().color256(110).bold(),
        inactive_item_prefix: style(" ".to_string()).for_stderr(),
        active_item_style: Style::new().for_stderr().color256(110),
        inactive_item_style: Style::new().for_stderr().dim(),
        hint_style: Style::new().for_stderr().dim(),
        values_style: Style::new().for_stderr().color256(110),
        ..ColorfulTheme::default()
    }
}

#[cfg(test)]
mod onboarding_tests {
    use super::*;

    /// R35: a scoped run (an explicit data directory, which `$TENZRO_DATA_DIR`
    /// also supplies) used to skip the autonomous identity registration and
    /// still print "Identity and wallet ready". It must name its node
    /// instead; nothing makes the step optional.
    #[test]
    fn a_scoped_autonomous_run_names_its_node_and_cannot_skip_the_identity_step() {
        let refused = autonomous_identity_rpc(None, true).unwrap_err().to_string();
        assert_eq!(refused, SCOPED_IDENTITY_NEEDS_RPC);
        assert!(refused.contains("cannot be skipped"), "{refused}");
        assert_eq!(
            autonomous_identity_rpc(Some("http://127.0.0.1:18545"), true).unwrap(),
            "http://127.0.0.1:18545"
        );
        // An unscoped run keeps reaching the public network.
        assert_eq!(
            autonomous_identity_rpc(None, false).unwrap(),
            "https://rpc.tenzro.com"
        );
    }

    /// R35: the identity step is not a function of `$TENZRO_DATA_DIR`. The
    /// source of the network path has no branch that reports the identity as
    /// ready without having registered or joined.
    #[test]
    fn the_network_path_has_no_branch_that_skips_the_identity_step() {
        let src = include_str!("setup.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !code.contains("skipping on-chain autonomous identity registration"),
            "the scoped-run skip is back"
        );
        let step = code
            .split("// ---- 2. Authority (identity and wallet, blocking)")
            .nth(1)
            .and_then(|s| s.split("wiz_done(\"Identity and wallet ready\")").next())
            .expect("the identity step is in the network path");
        assert!(
            step.contains("register_machine_identity") && step.contains("join.execute().await?"),
            "both operator modes must register or join before the step reports ready"
        );
        assert!(
            code.contains("\"tenzro_registerIdentity\""),
            "the machine identity registration is gone"
        );
        assert!(
            step.contains("agent_delegation_ready"),
            "both operator modes must register or join before the step reports ready"
        );
    }

    /// R35: a private-network join writes no service unit and saves no role
    /// on a machine that cannot hold the identity key, for the `ai` role as
    /// much as for the validator role. (Where the machine has a hardware key
    /// store the preflight can pass, so the refusal is not asserted there.)
    #[tokio::test]
    async fn a_private_join_without_a_hardware_key_store_writes_nothing() {
        if tenzro_device_key::signer::platform_backend().is_some() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let genesis = dir.path().join("genesis.toml");
        std::fs::write(&genesis, "chain_id = 1\n").unwrap();
        let cmd = SetupCmd::parse_from([
            "setup",
            "--yes",
            "--path",
            "private",
            "--genesis",
            genesis.to_str().unwrap(),
            "--bootstrap",
            "did:tenzro:machine:ab@https://relay.example",
            "--data-dir",
            dir.path().join("data").to_str().unwrap(),
        ]);
        let err = cmd
            .execute()
            .await
            .expect_err("a machine with no hardware key must be refused");
        assert!(
            err.to_string().contains("not ready") || err.to_string().contains("tenzro-node"),
            "unexpected refusal: {err}"
        );
        assert!(
            !dir.path().join("data").exists(),
            "a refused private join created the data directory"
        );
    }

    #[test]
    fn hardening_block_validator_is_last_to_be_killed_and_first_to_run() {
        let b = hardening_block("validator");
        for line in [
            "OOMScoreAdjust=-900",
            "CPUWeight=800",
            "IOWeight=800",
            "TasksMax=16384",
            "MemoryHigh=75%",
            "MemoryMax=88%",
            "MemorySwapMax=0",
        ] {
            assert!(b.contains(line), "missing {line} in {b}");
        }
    }

    #[test]
    fn hardening_block_models_node_gets_no_memory_cap() {
        let b = hardening_block("validator,ai");
        assert!(b.contains("OOMScoreAdjust=-900"));
        assert!(!b.contains("MemoryMax"));
        assert!(!b.contains("MemoryHigh"));
    }

    #[test]
    fn hardening_block_non_validator_is_protected_less() {
        let b = hardening_block("rpc");
        assert!(b.contains("OOMScoreAdjust=-200"));
        assert!(b.contains("CPUWeight=200"));
        assert!(!b.contains("-900"));
    }

    fn unit_paths() -> ServicePaths {
        ServicePaths {
            node: "/opt/tenzro/current/bin/tenzro-node".into(),
            tenzro: "/opt/tenzro/current/bin/tenzro".into(),
            install_dir: "/opt/tenzro".into(),
        }
    }

    #[test]
    fn the_systemd_unit_counts_each_start_before_the_node_and_a_failed_count_cannot_block_it() {
        let args = vec![
            "--roles".to_string(),
            "validator".to_string(),
            "--data-dir".to_string(),
            "/var/lib/tenzro".to_string(),
        ];
        let unit = systemd_unit_text(
            Path::new("/var/lib/tenzro"),
            &unit_paths(),
            &args,
            "validator",
            "tenzro",
        );
        // The leading "-" is what lets the node start when the count fails.
        let count = "\nExecStartPre=-/opt/tenzro/current/bin/tenzro update boot-check --install-dir /opt/tenzro --data-dir /var/lib/tenzro\n";
        let start = "\nExecStart=/opt/tenzro/current/bin/tenzro-node --roles validator --data-dir /var/lib/tenzro\n";
        let (counted, started) = (
            unit.find(count).expect("the unit counts the start"),
            unit.find(start).expect("the unit starts the node"),
        );
        assert!(
            counted < started,
            "the start is counted before the node runs"
        );
        assert_eq!(unit.matches("ExecStartPre=").count(), 1);
        assert!(unit.contains("\nUser=tenzro\n"));
        assert!(
            unit.contains("\nReadWritePaths=/var/lib/tenzro\n"),
            "the count writes only under the data directory"
        );
        assert_eq!(
            service::systemd_program(&unit),
            Some(PathBuf::from("/opt/tenzro/current/bin/tenzro-node"))
        );
    }

    #[test]
    fn the_launchd_agent_counts_each_start_and_then_becomes_the_node() {
        let args = vec![
            "--roles".to_string(),
            "user".to_string(),
            "--name".to_string(),
            "a <b> & c".to_string(),
        ];
        let plist = launchd_plist_text(Path::new("/Users/a/.tenzro"), &unit_paths(), &args);
        let expected = service::launchd_arguments(
            "/opt/tenzro/current/bin/tenzro",
            "/opt/tenzro",
            "/Users/a/.tenzro",
            "/opt/tenzro/current/bin/tenzro-node",
            &args,
        );
        assert_eq!(
            service::launchd_program_arguments(&plist).unwrap(),
            expected
        );
        assert_eq!(
            service::launchd_program(&plist),
            Some(PathBuf::from("/opt/tenzro/current/bin/tenzro-node"))
        );
        assert!(
            plist.contains("        <string>a &lt;b&gt; &amp; c</string>\n"),
            "an argument is written as text, never as markup"
        );
        assert!(plist.contains("<string>/Users/a/.tenzro/node.log</string>"));
    }

    #[cfg(unix)]
    #[test]
    fn a_versioned_install_is_named_through_current_and_not_through_a_release_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let bin = root.join("versions/0.2.1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("tenzro"), b"cli").unwrap();
        std::fs::write(bin.join("tenzro-node"), b"node").unwrap();
        std::os::unix::fs::symlink("versions/0.2.1", root.join("current")).unwrap();

        let p = service_paths_for(&bin.join("tenzro"));
        assert_eq!(
            p.node,
            root.join("current/bin/tenzro-node").display().to_string()
        );
        assert_eq!(
            p.tenzro,
            root.join("current/bin/tenzro").display().to_string()
        );
        assert_eq!(p.install_dir, root.display().to_string());
        assert!(
            !p.node.contains("versions"),
            "an update removes old release directories"
        );
    }

    #[test]
    fn a_plain_folder_install_names_the_node_beside_tenzro_or_the_usual_location() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let exe = dir.join(format!("tenzro{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"cli").unwrap();
        let p = service_paths_for(&exe);
        assert_eq!(
            p.node, "/usr/local/bin/tenzro-node",
            "no node beside this tenzro"
        );
        assert_eq!(p.tenzro, exe.display().to_string());
        assert_eq!(p.install_dir, dir.display().to_string());

        let node = dir.join(format!("tenzro-node{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&node, b"node").unwrap();
        assert_eq!(service_paths_for(&exe).node, node.display().to_string());
    }
}
