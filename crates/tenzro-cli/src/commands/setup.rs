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

use anyhow::{anyhow, Result};
use clap::Parser;
use console::{style, Style};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use rand::Rng;

use crate::commands::hardware::{detect_hardware_profile, HardwareProfile};
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

    /// Participation mode on the public network.
    #[arg(long, value_parser = ["consume", "provide", "validate"])]
    pub mode: Option<String>,

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

    async fn run_network_path(&self, interactive: bool, hw: &HardwareProfile) -> Result<()> {
        let name = match &self.name {
            Some(n) => n.clone(),
            None => prompt_string(interactive, "Display name", "Tenzro User")?,
        };

        if !hw.gpus.is_empty() || hw.unified_memory {
            wiz_note(
                "Accelerator hardware detected — this machine can provide inference to the network",
            );
            wiz_gap();
        }

        let mode = match self.mode.as_deref() {
            Some(m) => m.to_string(),
            None => {
                let items = [
                    "Consume — use models, agents, and services on the network",
                    "Provide — serve models from this machine and earn TNZO",
                    "Validate — run a validator node securing the network",
                ];
                let default = if !hw.gpus.is_empty() || hw.unified_memory { 1 } else { 0 };
                match prompt_select(interactive, "How do you want to participate?", &items, default)? {
                    1 => "provide".to_string(),
                    2 => "validate".to_string(),
                    _ => "consume".to_string(),
                }
            }
        };

        match mode.as_str() {
            "provide" => {
                wiz_section("Provider setup");
                let join = JoinCmd {
                    rpc: self.rpc.clone(),
                    name,
                    origin: "cli".to_string(),
                    r#type: "human".to_string(),
                    provider: true,
                };
                join.execute().await
            }
            "validate" => self.run_public_validator(interactive, &name).await,
            _ => {
                wiz_section("Joining the Tenzro network");
                let join = JoinCmd {
                    rpc: self.rpc.clone(),
                    name,
                    origin: "cli".to_string(),
                    r#type: "human".to_string(),
                    provider: false,
                };
                join.execute().await
            }
        }
    }

    async fn run_public_validator(&self, interactive: bool, name: &str) -> Result<()> {
        wiz_section("Validator setup");

        let default_dir = default_home().join(".tenzro").join("node");
        let data_dir = match &self.data_dir {
            Some(d) => d.clone(),
            None => PathBuf::from(prompt_string(
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
        wiz_kv("Validator pubkey", &format!("0x{}", hex::encode(&pubkeys.ed25519)));
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
        wiz_note(&format!("   A unit file was written to {}", unit_path.display()));

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

        let base = default_home()
            .join(".tenzro")
            .join("networks")
            .join(&network_name);
        let data_dir = self.data_dir.clone().unwrap_or_else(|| base.join("data"));

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

        std::fs::create_dir_all(&base)
            .map_err(|e| anyhow!("create {}: {}", base.display(), e))?;

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
            g.push_str("amount_per_request = 100\ncooldown_seconds = 86400\nenabled = true\n");
            std::fs::write(&genesis_path, g)
                .map_err(|e| anyhow!("write {}: {}", genesis_path.display(), e))?;
            wiz_done(&format!("Genesis written to {}", genesis_path.display()));
        }

        let unit_path =
            write_service_unit(&data_dir, Some(&genesis_path), None, "validator,ai")?;

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
            format!("  --genesis ~/.tenzro/networks/{}/genesis.toml \\", network_name),
            format!("  --data-dir ~/.tenzro/networks/{}/data \\", network_name),
            format!("  --boot-nodes /ip4/{}/tcp/9000/p2p/{}", lan_ip, peer_id),
        ]);
        wiz_note("Optional: run the node as a service.");
        wiz_note(&format!("A unit file was written to {}", unit_path.display()));

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
                ))
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
                ))
            }
        };
        if bootstrap.trim().is_empty() {
            return Err(anyhow!("a bootstrap peer multiaddr is required to join a private network"));
        }

        let default_dir = default_home().join(".tenzro").join("node");
        let data_dir = match &self.data_dir {
            Some(d) => d.clone(),
            None => PathBuf::from(prompt_string(
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

        let unit_path =
            write_service_unit(&data_dir, Some(&genesis), Some(&bootstrap), roles)?;

        wiz_section("Start your node");
        wiz_cmd(&[
            format!("tenzro-node --roles {} \\", roles),
            format!("  --data-dir {} \\", data_dir.display()),
            format!("  --genesis {} \\", genesis.display()),
            format!("  --boot-nodes {}", bootstrap),
        ]);
        wiz_note("Optional: run the node as a service.");
        wiz_note(&format!("A unit file was written to {}", unit_path.display()));

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
        &format!("{} ({} cores / {} threads)", hw.cpu_model, hw.cpu_cores, hw.cpu_threads),
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
    wiz_kv("Storage available", &format!("{:.0} GB", hw.storage_available_gb));
    wiz_kv(
        "TEE",
        &hw.tee_type.clone().unwrap_or_else(|| "not available".to_string()),
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

fn default_home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
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
    let keypair =
        tenzro_network::service::load_or_generate_keypair(&Some(data_dir.to_path_buf()))?;
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
    println!("{}", style(format!("╭{}╮", "─".repeat(BANNER_INNER_WIDTH))).dim());
    wiz_box_line("", "");
    wiz_box_line("Tenzro Setup", &style("Tenzro Setup").cyan().bold().to_string());
    wiz_box_line(
        "Join, provide, validate, or bootstrap a network",
        &style("Join, provide, validate, or bootstrap a network")
            .dim()
            .to_string(),
    );
    wiz_box_line("", "");
    println!("{}", style(format!("╰{}╯", "─".repeat(BANNER_INNER_WIDTH))).dim());
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
