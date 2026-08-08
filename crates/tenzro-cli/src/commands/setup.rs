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
//!    a bootstrap peer supplied by the network operator.
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
use crate::config;
use crate::output;

const FAUCET_SENTINEL_ADDRESS: &str =
    "0000000000000000000000000000000000000000000000000000000000ffffff";

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

    /// Machine name — a bare DNS label (3-63 chars, `[a-z0-9-]`). When this
    /// node is public it is reachable at `<machine-name>.<public suffix>`.
    #[arg(long)]
    pub machine_name: Option<String>,

    /// Whether this node is reachable from the public internet under its
    /// machine name, or stays reachable only on the local network.
    #[arg(long, value_parser = ["public", "private"])]
    pub visibility: Option<String>,

    /// Who operates this machine: `self` (a human holds the passkey) or
    /// `autonomous` (the machine answers for itself via an attestable
    /// hardware root). `autonomous` requires a usable TPM.
    #[arg(long, value_parser = ["self", "autonomous"])]
    pub operator: Option<String>,

    /// Comma-separated roles this node serves, e.g.
    /// `validator,ai,storage,database,cloud`.
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
    /// random five-digit id so it cannot collide with the public
    /// testnet (1337).
    #[arg(long)]
    pub chain_id: Option<u64>,

    /// Node data directory. Defaults depend on the chosen path.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Genesis stake for the founding validator (whole TNZO units).
    #[arg(long, default_value_t = 1000)]
    pub stake: u64,

    /// Bootstrap peer multiaddr of an existing private network
    /// (e.g. /ip4/192.168.1.10/tcp/9000/p2p/12D3Koo...).
    #[arg(long)]
    pub bootstrap: Option<String>,

    /// Path to the genesis.toml of an existing private network.
    #[arg(long)]
    pub genesis: Option<PathBuf>,

    /// Non-interactive: accept defaults, take everything else from flags.
    #[arg(long)]
    pub yes: bool,
}

impl SetupCmd {
    pub async fn execute(&self) -> Result<()> {
        wiz_intro();

        let interactive = !self.yes && atty::is(atty::Stream::Stdin);

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
            "local" => self.run_local_path(interactive).await,
            "private" => self.run_private_path(interactive).await,
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
                    "Public — also reachable from the internet by machine name",
                ];
                prompt_select(interactive, "How should this node be reachable?", &items, 0)? == 1
            }
        };
        if public {
            wiz_kv("Reachable", "Public + local network");
            wiz_note(
                "The machine name is claimed on-chain, so no node operator can take it from you.",
            );
        } else {
            wiz_kv("Reachable", "Local network only");
            wiz_note("No public name is claimed. You can turn this on later.");
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
                        "Autonomous — the machine answers for itself via its TPM",
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
        wiz_section("Identity and wallet");
        if autonomous {
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
                .unwrap_or_else(|| "https://rpc.tenzro.xyz".to_string());
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

        // ---- 5. Roles ------------------------------------------------
        wiz_section("Roles");
        let roles = self.resolve_roles(interactive, hw)?;
        wiz_kv("Serving", &roles.to_string());
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

        // ---- 7. Claim the public name ---------------------------------
        //
        // Done here, after identity exists, because the claim is a signed
        // transaction from the operator's own account — there is nothing to
        // sign with until the identity step has completed.
        if public {
            wiz_section("Public name");
            match self.claim_machine_name(&machine_name).await {
                Ok(true) => {
                    wiz_done(&format!("Claimed `{machine_name}` on-chain"));
                    wiz_note("Ownership is settled by block order, so no operator can take it.");
                }
                Ok(false) => {}
                Err(e) => {
                    // A failed claim must not abort a setup that otherwise
                    // succeeded — the node still runs, just without a public
                    // name, and the operator can retry the one command.
                    wiz_warn(&format!("Could not claim `{machine_name}`: {e}"));
                    wiz_note(&format!(
                        "Retry later with: tenzro node alias claim {machine_name}"
                    ));
                }
            }
            wiz_gap();
        }

        if roles.is_validator() {
            return self.run_public_validator(interactive, &name).await;
        }

        wiz_section("Next steps");
        wiz_note("Start the node with:");
        wiz_cmd(&[format!("tenzro node start --roles {roles}")]);
        if public {
            wiz_note("Then point the name at it — the node signs its own consent, so a name");
            wiz_note("cannot be bound to a machine its operator does not control:");
            wiz_cmd(&[format!("tenzro node alias bind {machine_name}")]);
        }
        wiz_outro("Setup complete");
        Ok(())
    }

    /// Claim the machine name on-chain, using the wallet setup just created.
    ///
    /// Returns `Ok(false)` when there is nothing to do (the operator already
    /// holds the name). Any real failure is surfaced to the caller, which
    /// treats it as non-fatal — a node without a public name is still a
    /// working node.
    async fn claim_machine_name(&self, machine_name: &str) -> Result<bool> {
        let cfg = config::load_config();
        let Some(from) = cfg.wallet_address.clone() else {
            return Err(anyhow!(
                "no wallet address on this machine yet — identity setup must complete first"
            ));
        };
        let rpc_url = cfg
            .endpoint
            .clone()
            .or_else(|| self.rpc.clone())
            .unwrap_or_else(|| "https://rpc.tenzro.xyz".to_string());

        let claim = crate::commands::node_alias::AliasClaimCmd {
            name: machine_name.to_string(),
            from,
            did: cfg.did.clone(),
            expose: Vec::new(),
            rpc: rpc_url,
        };
        claim.execute().await.map(|()| true)
    }

    /// Prompt for and validate a machine name.
    ///
    /// Validated with the DNS-label rule rather than the username rule: a
    /// name accepted by the latter (which allows `_`) would claim fine and
    /// then never resolve as a hostname.
    fn resolve_machine_name(&self, interactive: bool) -> Result<String> {
        let default = default_machine_name();
        for attempt in 0..5 {
            let candidate = match (&self.machine_name, attempt) {
                (Some(n), 0) => n.trim().to_ascii_lowercase(),
                _ => prompt_string(interactive, "Machine name", &default)?
                    .trim()
                    .to_ascii_lowercase(),
            };
            match tenzro_types::node_alias::validate_alias(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(e) => {
                    if !interactive {
                        return Err(anyhow!("invalid --machine-name '{candidate}': {e}"));
                    }
                    wiz_warn(&format!("{e}"));
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
        let options: [(&str, NetworkRole); 6] = [
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
                "Database provider — host managed databases",
                NetworkRole::DatabaseProvider,
            ),
            (
                "Cloud provider — host sites, functions and apps",
                NetworkRole::CloudProvider,
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
        let mut cfg = config::load_config();
        cfg.display_name = Some(display_name.to_string());
        cfg.machine_name = Some(machine_name.to_string());
        cfg.public = Some(public);
        cfg.operator_mode = Some(if autonomous { "autonomous" } else { "self" }.to_string());
        cfg.roles = Some(roles.to_string());
        // Keep the legacy single-valued field consistent for the commands
        // that still read it.
        cfg.role = Some(roles.primary().as_str().to_string());
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
                    .unwrap_or_else(|| "https://rpc.tenzro.xyz".to_string()),
            );
        }
        config::save_config(&cfg)
    }

    async fn run_public_validator(&self, interactive: bool, name: &str) -> Result<()> {
        wiz_section("Validator setup");

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

        let keyset = ensure_keyset(&data_dir)?;
        let pubkeys = keyset.pubkeys();
        let peer_id = local_peer_id(&data_dir)?;

        wiz_gap();
        wiz_kv("Data directory", &data_dir.display().to_string());
        wiz_kv(
            "Validator pubkey",
            &format!("0x{}", hex::encode(&pubkeys.ed25519)),
        );
        wiz_kv("Peer id", &peer_id);

        let unit_path = write_service_unit(&data_dir, None, None, "validator")?;

        wiz_section("Next steps");
        wiz_note("1. Start your validator (bootstrap discovery is automatic):");
        wiz_cmd(&[format!(
            "tenzro-node --roles validator --data-dir {}",
            data_dir.display()
        )]);
        wiz_note("2. Fund and bond stake — validators join the active set through");
        wiz_note("   stake admission at the next epoch:");
        wiz_cmd(&[
            "tenzro faucet             # testnet TNZO".to_string(),
            "tenzro stake deposit 10000".to_string(),
        ]);
        wiz_note("3. Optional: run the node as a service.");
        wiz_note(&format!(
            "   A unit file was written to {}",
            unit_path.display()
        ));

        let mut cfg = config::load_config();
        cfg.endpoint = Some("http://127.0.0.1:8545".to_string());
        cfg.display_name = Some(name.to_string());
        cfg.role = Some("validator".to_string());
        config::save_config(&cfg)?;
        wiz_outro("Setup complete — configuration saved");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Path 2 — local / sovereign network bootstrap
    // ------------------------------------------------------------------

    async fn run_local_path(&self, interactive: bool) -> Result<()> {
        wiz_section("Local network setup");

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

        let keyset = ensure_keyset(&data_dir)?;
        let pubkeys = keyset.pubkeys();
        let peer_id = local_peer_id(&data_dir)?;
        let lan_ip = detect_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string());

        std::fs::create_dir_all(&base).map_err(|e| anyhow!("create {}: {}", base.display(), e))?;

        let genesis_path = base.join("genesis.toml");
        if genesis_path.exists() {
            wiz_warn(&format!(
                "Genesis already exists at {} — keeping it",
                genesis_path.display()
            ));
        } else {
            let founder_address = hex::encode(&pubkeys.ed25519);
            let mut g = String::new();
            g.push_str(&format!(
                "version = 3\nchain_id = {}\ntimestamp = 0\n\n",
                chain_id
            ));
            g.push_str(&format!("# founding validator (peer_id={})\n", peer_id));
            g.push_str(&pubkeys.to_genesis_toml(self.stake));
            g.push_str("\n[[accounts]]\n");
            g.push_str(&format!("address = \"{}\"\n", founder_address));
            g.push_str("balance = 1000000\n");
            g.push_str("\n[faucet]\n");
            g.push_str(&format!("address = \"{}\"\n", FAUCET_SENTINEL_ADDRESS));
            g.push_str("amount_per_request = 2000\ncooldown_seconds = 86400\nenabled = true\n");
            std::fs::write(&genesis_path, g)
                .map_err(|e| anyhow!("write {}: {}", genesis_path.display(), e))?;
            wiz_done(&format!("Genesis written to {}", genesis_path.display()));
        }

        let unit_path = write_service_unit(&data_dir, Some(&genesis_path), None, "validator,ai")?;

        wiz_gap();
        wiz_kv("Network", &network_name);
        wiz_kv("Chain id", &chain_id.to_string());
        wiz_kv("Data directory", &data_dir.display().to_string());
        wiz_kv("Peer id", &peer_id);
        wiz_kv("LAN address", &lan_ip);

        wiz_section("Start your network");
        wiz_note("On this machine (founding validator):");
        wiz_cmd(&[format!(
            "tenzro-node --roles validator,ai --data-dir {} --genesis {}",
            data_dir.display(),
            genesis_path.display()
        )]);
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
            format!("  --boot-nodes /ip4/{}/tcp/9000/p2p/{}", lan_ip, peer_id),
        ]);
        wiz_note("Optional: run the node as a service.");
        wiz_note(&format!(
            "A unit file was written to {}",
            unit_path.display()
        ));

        let mut cfg = config::load_config();
        cfg.endpoint = Some("http://127.0.0.1:8545".to_string());
        cfg.role = Some("validator".to_string());
        config::save_config(&cfg)?;
        wiz_outro("Setup complete — configuration saved");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Path 3 — join an existing private network
    // ------------------------------------------------------------------

    async fn run_private_path(&self, interactive: bool) -> Result<()> {
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
                "Bootstrap peer multiaddr (from the network operator)",
                "",
            )?,
            None => {
                return Err(anyhow!(
                    "--bootstrap is required in non-interactive mode (multiaddr of an existing peer)"
                ));
            }
        };
        if bootstrap.trim().is_empty() {
            return Err(anyhow!(
                "a bootstrap peer multiaddr is required to join a private network"
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
            let keyset = ensure_keyset(&data_dir)?;
            let pubkeys = keyset.pubkeys();
            wiz_gap();
            wiz_note("Send this stanza to the network operator for inclusion in genesis:");
            println!();
            println!("{}", pubkeys.to_genesis_toml(self.stake));
        }

        let unit_path = write_service_unit(&data_dir, Some(&genesis), Some(&bootstrap), roles)?;

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
        cfg.role = Some(if roles.starts_with("validator") {
            "validator".to_string()
        } else {
            "provider".to_string()
        });
        config::save_config(&cfg)?;
        wiz_outro("Setup complete — configuration saved");
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

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
                    "no TPM (Apple Secure Enclave is not yet wired as a machine anchor)".to_string()
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

/// Minimal `which`, so the CLI need not depend on `tenzro-tee` (whose TPM
/// surface is a node-side concern) just to test for a binary.
fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
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
    if tenzro_types::node_alias::validate_alias(&cleaned).is_ok() {
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

/// Load the validator keyset from `data_dir` if all three key files
/// exist, otherwise generate and persist a fresh one. Reruns of the
/// wizard reuse the existing identity instead of forking it.
fn ensure_keyset(data_dir: &Path) -> Result<tenzro_node::keygen::ValidatorKeyset> {
    use tenzro_node::keygen;

    let have_all = ["validator_key", "validator_pq_key", "validator_bls_key"]
        .iter()
        .all(|f| data_dir.join(f).exists());

    if have_all {
        let keypair = keygen::load_validator_keypair(data_dir)?;
        let pq = keygen::load_validator_pq_key(data_dir)?;
        let bls = keygen::load_validator_bls_key(data_dir)?;
        wiz_note("Validator keys already present — reusing existing identity");
        Ok(keygen::ValidatorKeyset { keypair, pq, bls })
    } else {
        let keyset = keygen::generate_and_persist_keyset(data_dir, false)?;
        wiz_done("Generated validator keys (Ed25519 + ML-DSA-65 + BLS12-381)");
        Ok(keyset)
    }
}

/// Derive the libp2p peer id this node will announce, creating and
/// persisting `{data_dir}/p2p_key` if it does not exist yet — so the
/// join command printed for peers is valid before the node's first start.
fn local_peer_id(data_dir: &Path) -> Result<String> {
    let keypair = tenzro_network::service::load_or_generate_keypair(&Some(data_dir.to_path_buf()))?;
    Ok(keypair.public().to_peer_id().to_string())
}

/// Best-effort LAN address discovery: a connected UDP socket reveals the
/// interface the OS would route external traffic through. No packets are
/// sent.
fn detect_lan_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
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

/// Write a launchd plist (macOS) or systemd unit (Linux) into `data_dir`
/// with install instructions in the file header. The wizard never
/// installs or starts the service itself.
fn write_service_unit(
    data_dir: &Path,
    genesis: Option<&Path>,
    bootstrap: Option<&str>,
    roles: &str,
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
ExecStart={exec}
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
"#,
            unit = data_dir.join("tenzro-node.service").display(),
            exec = exec,
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
