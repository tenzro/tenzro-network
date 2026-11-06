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
use crate::config;
use crate::output;

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

    /// Who operates this machine: `self` (a human holds the passkey) or
    /// `autonomous` (the machine answers for itself via an attestable
    /// hardware root). `autonomous` requires a usable TPM 2.0 or, on Apple
    /// hardware, a Secure Enclave.
    #[arg(long, value_parser = ["self", "autonomous"])]
    pub operator: Option<String>,

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
    /// it: `did:tenzro:machine:<id>@<relay url>`.
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
}

impl SetupCmd {
    pub async fn execute(&self) -> Result<()> {
        wiz_intro();

        let interactive = !self.yes && std::io::IsTerminal::is_terminal(&std::io::stdin());

        // Step 1 — detect what this machine can do.
        let spinner = output::create_spinner("Detecting hardware...");
        let hw = detect_hardware_profile().await;
        spinner.finish_and_clear();
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

    /// Public-network path.
    ///
    /// The step order is a dependency order, not a preference:
    ///
    /// 1. **Machine name** — needed before anything can address this node.
    /// 2. **Public or private** — decides whether the name is claimed at all.
    /// 3. **Who operates it** — autonomous is only offered when the hardware
    ///    can actually anchor an identity without a human.
    /// 4. **Identity and wallet** — *blocking*. Everything after this point
    ///    needs an identity to sign as, so a half-finished ceremony must stop
    ///    the wizard rather than leave a node with roles it cannot claim.
    /// 5. **Roles** — what this node serves.
    /// 6. **Access model** — how the served resources are paid for.
    async fn run_network_path(&self, interactive: bool, hw: &HardwareProfile) -> Result<()> {
        let name = match &self.name {
            Some(n) => n.clone(),
            None => prompt_string(interactive, "Display name", "Tenzro User")?,
        };

        // ---- 1. Machine name -----------------------------------------
        wiz_section("Machine name");
        wiz_note("A short name for this machine, used to address it on the network.");
        let machine_name = self.resolve_machine_name(interactive)?;
        wiz_kv("Machine", &machine_name);
        wiz_gap();

        // ---- 2. Public or private ------------------------------------
        wiz_section("Reachability");
        let public = match self.visibility.as_deref() {
            Some(v) => v == "public",
            None => {
                let items = [
                    "Private — reachable on your local network only",
                    "Public — also reachable from the internet",
                ];
                prompt_select(interactive, "How should this node be reachable?", &items, 0)? == 1
            }
        };
        if public {
            wiz_kv("Reachable", "Public + local network");
        } else {
            wiz_kv("Reachable", "Local network only");
            wiz_note("You can turn public access on later.");
        }
        wiz_gap();

        // ---- 3. Who operates this machine ----------------------------
        wiz_section("Operator");
        let anchor = MachineAnchorOptions::detect(hw);
        let autonomous = match self.operator.as_deref() {
            Some("autonomous") => {
                if !anchor.autonomous_available {
                    return Err(anyhow!(
                        "--operator autonomous is not available on this machine: {}",
                        anchor.reason
                    ));
                }
                true
            }
            Some(_) => false,
            None => {
                if anchor.autonomous_available {
                    let items = [
                        "I operate this machine — my passkey controls it",
                        "Autonomous — the machine answers for itself via its TPM or Secure Enclave",
                    ];
                    prompt_select(interactive, "Who operates this machine?", &items, 0)? == 1
                } else {
                    // Say why rather than silently offering one option, so
                    // the operator can fix it if they wanted autonomy.
                    wiz_note(&format!(
                        "Autonomous operation unavailable — {}",
                        anchor.reason
                    ));
                    false
                }
            }
        };
        wiz_kv(
            "Operator",
            if autonomous {
                "Autonomous (hardware-rooted)"
            } else {
                "You (passkey)"
            },
        );
        wiz_gap();

        // ---- 4. Roles ------------------------------------------------
        //
        // Chosen *before* identity because provider registration is part of
        // joining: `JoinCmd`'s provider flow does hardware detection,
        // funding, the compute bond, provider registration, default pricing
        // and the first model serve, and it needs to know at call time
        // whether this operator provides anything. Selecting roles is only a
        // prompt — nothing here needs an identity yet — so asking first
        // costs nothing and keeps that flow reachable.
        wiz_section("Roles");
        let roles = self.resolve_roles(interactive, hw)?;
        wiz_kv("Serving", &roles.to_string());
        wiz_gap();

        // ---- 5. Identity and wallet (blocking) -----------------------
        if autonomous {
            self.run_preflight(interactive, hw)?;
        }
        wiz_section("Identity and wallet");
        if autonomous && self.data_dir.is_some() {
            // A scoped run (explicit --data-dir) must not anchor a real
            // on-chain machine identity — that would register against the live
            // network from an isolated/test sandbox. Skip the on-chain step;
            // the local keyset + scoped config are still written.
            wiz_note("Scoped --data-dir run: skipping on-chain autonomous identity registration.");
        } else if autonomous {
            // Deliberately not the `join` path: that provisions a MicroNode
            // whose `participant_type` is human/agent/bot, none of which
            // describes a machine that answers for itself. `registerIdentity`
            // with `identity_type: "autonomous"` is the primitive that
            // actually collects the hardware identity, refuses when it is not
            // attestable, and anchors the machine as `HardwareRooted`.
            wiz_note("Registering this machine against its hardware root...");
            // This is the *public network* path, so it must reach the public
            // network — the same endpoint `JoinCmd` resolves to for a
            // non-provider join. Defaulting to loopback here would have made
            // an autonomous machine register against a node that need not
            // exist, while the passkey branch beside it joined the real
            // network: the same wizard step landing on two different networks
            // depending only on which operator mode was chosen.
            let rpc_url = self
                .rpc
                .clone()
                .unwrap_or_else(|| "https://rpc.tenzro.com".to_string());
            let rpc = crate::rpc::RpcClient::new(&rpc_url);
            let spinner = output::create_spinner("Anchoring machine identity...");
            let result: serde_json::Value = rpc
                .call(
                    "tenzro_registerIdentity",
                    serde_json::json!({
                        "identity_type": "autonomous",
                        "display_name": name,
                    }),
                )
                .await
                .map_err(|e| {
                    anyhow!(
                        "autonomous registration failed: {e}\n\
                         The machine must present an attestable hardware root; \
                         re-run with --operator self to use a passkey instead."
                    )
                })?;
            spinner.finish_and_clear();
            if let Some(did) = result
                .get("identity")
                .and_then(|i| i.get("did"))
                .and_then(|v| v.as_str())
            {
                wiz_kv("Machine DID", did);
            }
        } else {
            wiz_note("Opening your browser to create a passkey.");
            wiz_note("No local authenticator? Scan the QR code shown there with your phone.");
            let join = JoinCmd {
                rpc: self.rpc.clone(),
                name: name.clone(),
                origin: "cli".to_string(),
                r#type: "human".to_string(),
                // Anyone serving a paid role joins as a provider, which is
                // what runs hardware detection, the compute bond, provider
                // registration, default pricing and the first model serve.
                // Hardcoding `false` here silently removed all of that.
                provider: roles.is_provider(),
            };
            join.execute().await?;
        }
        wiz_done("Identity and wallet ready");
        wiz_gap();

        // ---- 6. Access model -----------------------------------------
        // Only meaningful for a node that actually provides something; a
        // pure client or validator has nothing to price.
        let access = if roles.is_provider() {
            wiz_section("Access");
            let a = self.resolve_access_models(interactive)?;
            wiz_kv("Offered as", &a.join(", "));
            wiz_gap();
            a
        } else {
            Vec::new()
        };

        self.persist_setup(&name, &machine_name, public, autonomous, &roles, &access)?;

        if roles.is_validator() {
            return self.run_public_validator(interactive, &name, hw).await;
        }

        let data_dir = match &self.data_dir {
            Some(d) => tenzro_types::paths::expand_tilde(d),
            None => tenzro_types::paths::default_data_dir(),
        };
        if self.wants_apply(interactive)? {
            let unit = write_service_unit(&data_dir, None, None, &roles.to_string(), &[])?;
            self.apply_service(interactive, hw, &unit, autonomous).await?;
        } else {
            wiz_section("Next steps");
            wiz_note("Start the node with:");
            wiz_cmd(&[format!("tenzro node start --roles {roles}")]);
        }
        wiz_outro("Setup complete");
        Ok(())
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
            preflight::Line::Check(preflight::Level::Todo, text) => wiz_note(&format!("To do: {text}")),
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
                    "this machine's TPM keys are not created yet. Run `tenzro-node tpm provision` \
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

    /// Multi-select the roles this node serves, returning a real `RoleSet`.
    ///
    /// Returning a typed `RoleSet` rather than a hand-built string means a
    /// bad role is caught here instead of when the operator later runs the
    /// printed `tenzro-node --roles ...` command.
    fn resolve_roles(&self, interactive: bool, hw: &HardwareProfile) -> Result<RoleSet> {
        if let Some(raw) = &self.roles {
            return raw
                .parse::<RoleSet>()
                .map_err(|e| anyhow!("invalid --roles '{raw}': {e}"));
        }

        // `--mode` is the older, narrower spelling of the same choice. It is
        // honoured rather than ignored: silently accepting a flag and doing
        // nothing with it is worse than either supporting it or rejecting it,
        // because a script keeps "working" while doing something else.
        if let Some(mode) = self.mode.as_deref() {
            let roles = match mode {
                "provide" => RoleSet::from(NetworkRole::ModelProvider),
                "validate" => RoleSet::from(NetworkRole::Validator),
                // `consume` is a participant with no serving obligations.
                _ => RoleSet::client(),
            };
            wiz_note(&format!("--mode {mode} selected roles: {roles}"));
            return Ok(roles);
        }

        let has_accelerator = !hw.gpus.is_empty() || hw.unified_memory;
        let options: [(&str, NetworkRole); 4] = [
            (
                "AI provider — serve models and earn TNZO",
                NetworkRole::ModelProvider,
            ),
            (
                "Compute provider — rent out accelerator time",
                NetworkRole::ComputeProvider,
            ),
            (
                "Storage provider — host network storage",
                NetworkRole::StorageProvider,
            ),
            (
                "Validator — help secure the network",
                NetworkRole::Validator,
            ),
        ];
        let labels: Vec<&str> = options.iter().map(|(l, _)| *l).collect();
        // Pre-check what the hardware is obviously suited to; the operator
        // stays free to change it.
        let defaults: Vec<bool> = options
            .iter()
            .map(|(_, r)| has_accelerator && *r == NetworkRole::ModelProvider)
            .collect();

        let picked = prompt_multiselect(
            interactive,
            "What should this node do? (space to toggle, enter to confirm)",
            &labels,
            &defaults,
        )?;

        let chosen: Vec<NetworkRole> = picked.iter().map(|&i| options[i].1).collect();
        if chosen.is_empty() {
            // An empty set is a client — a legitimate answer, and RoleSet
            // already models it.
            wiz_note("No serving roles selected — joining as a participant.");
        }
        Ok(RoleSet::from_roles(chosen))
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
        autonomous: bool,
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
        cfg.operator_mode = Some(if autonomous { "autonomous" } else { "self" }.to_string());
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
            &format!("{} (registered by the node itself)", crate::rpc::format_tnzo(stake_wei)),
        );

        // The node registers itself on boot with its own hardware keys when
        // the unit carries `--validator-self-stake`; nothing is pasted by hand.
        let extra = [
            "--validator-self-stake".to_string(),
            stake_wei.to_string(),
        ];
        let unit_path = write_service_unit(&data_dir, None, None, "validator", &extra)?;

        let need = StakeNeed {
            role: "validator".to_string(),
            required_wei: stake_wei + VALIDATOR_GAS_RESERVE_WEI,
            balance_wei: balance,
            account: account.clone(),
        };
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
        for step in validator_next_steps(&data_dir, &unit_path, &account, stake_wei, need.is_met()) {
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
            self.apply_service(interactive, hw, &unit_path, true).await?;
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

        let unit_path = write_service_unit(&data_dir, Some(&genesis_path), None, "validator,ai", &[])?;

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
                "{} does not exist yet — copy it from the network operator before starting the node",
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

        if roles.starts_with("validator") {
            self.run_preflight(interactive, hw)?;
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

        let unit_path = write_service_unit(&data_dir, Some(&genesis), Some(&bootstrap), roles, &[])?;

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
            self.apply_service(interactive, hw, &unit_path, roles.starts_with("validator"))
                .await?;
        }
        wiz_outro("Setup complete — configuration saved");
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

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
            commands: if funded { Vec::new() } else { vec![account.to_string()] },
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
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
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
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("tenzro-node");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    which_on_path("tenzro-node")
}

/// Resolve the `tenzro-node` binary path for service units: prefer a
/// sibling of the current executable, fall back to PATH lookup semantics
/// via a plain name (systemd) or /usr/local/bin (launchd requires an
/// absolute path).
fn node_binary_path() -> String {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("tenzro-node");
        if candidate.exists() {
            return candidate.display().to_string();
        }
    }
    "/usr/local/bin/tenzro-node".to_string()
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

    let binary = node_binary_path();
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

    let path = if std::env::consts::OS == "macos" {
        let plist_args = args
            .iter()
            .map(|a| format!("        <string>{}</string>", a))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Install:
       cp {plist} ~/Library/LaunchAgents/network.tenzro.node.plist
       launchctl load ~/Library/LaunchAgents/network.tenzro.node.plist -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>network.tenzro.node</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
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
            binary = binary,
            plist_args = plist_args,
            data_dir = data_dir.display(),
        );
        let p = data_dir.join("network.tenzro.node.plist");
        std::fs::write(&p, content).map_err(|e| anyhow!("write {}: {}", p.display(), e))?;
        p
    } else {
        let exec = format!("{} {}", binary, args.join(" "));
        let content = format!(
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

[Install]
WantedBy=multi-user.target
"#,
            unit = data_dir.join("tenzro-node.service").display(),
            exec = exec,
            user = service_user()?,
            data_dir = data_dir.display(),
        );
        let p = data_dir.join("tenzro-node.service");
        std::fs::write(&p, content).map_err(|e| anyhow!("write {}: {}", p.display(), e))?;
        p
    };

    Ok(path)
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
        prompt_prefix: style("◆".to_string()).for_stderr().cyan(),
        success_prefix: style("◇".to_string()).for_stderr().green(),
        error_prefix: style("▲".to_string()).for_stderr().red(),
        active_item_prefix: style("❯".to_string()).for_stderr().cyan().bold(),
        inactive_item_prefix: style(" ".to_string()).for_stderr(),
        active_item_style: Style::new().for_stderr().cyan(),
        inactive_item_style: Style::new().for_stderr().dim(),
        hint_style: Style::new().for_stderr().dim(),
        values_style: Style::new().for_stderr().cyan(),
        ..ColorfulTheme::default()
    }
}
