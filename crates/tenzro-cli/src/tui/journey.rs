//! The steps of each first-run path, as data.
//!
//! `plan` is a pure function of the machine, the network check and the
//! person's options. It returns the ordered steps (what each does, why, the
//! exact command, whether it needs a typed confirmation, whether it may be
//! skipped) or, when the path cannot work on this machine, the plain reason
//! and what to do instead. The screens only draw and run what `plan` says, so
//! every path is testable without a terminal.
//!
//! The steps call the commands that already exist: `tenzro setup` for the
//! wizard's own logic, and the `tenzro-node` subcommands for the TPM, the key
//! holder and graceful exit. Nothing here reimplements them, and nothing here
//! stores a secret.

use std::path::PathBuf;

use super::detect::{KeyRoot, Machine, Net};

/// The one question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    UseNetwork,
    Provide,
    Validate,
    Local,
}

impl Path {
    pub const ALL: [Path; 4] = [Path::UseNetwork, Path::Provide, Path::Validate, Path::Local];

    pub fn label(self) -> &'static str {
        match self {
            Path::UseNetwork => "Use the network",
            Path::Provide => "Provide compute",
            Path::Validate => "Run a validator",
            Path::Local => "Try a local chain",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Path::UseNetwork => "Get a wallet and identity, then use models, payments and agents. No special hardware.",
            Path::Provide => "Serve AI models from this machine and get paid for the work. Needs a hardware key and a node.",
            Path::Validate => "Help run the chain. Needs a hardware key, a node, stake, and approval during the preview.",
            Path::Local => "Run a private chain on this machine to learn and build. Nothing leaves the machine.",
        }
    }
}

/// Which program a step runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prog {
    /// This executable.
    Cli,
    /// `tenzro-node`, next to this executable or on PATH.
    Node,
    /// Any other program on PATH.
    Other(&'static str),
}

impl Prog {
    pub fn name(&self) -> &str {
        match self {
            Prog::Cli => "tenzro",
            Prog::Node => "tenzro-node",
            Prog::Other(n) => n,
        }
    }
}

/// What a step does when run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing to run: read, then continue.
    None,
    /// Run a command and show its output.
    Exec {
        prog: Prog,
        args: Vec<String>,
        /// Start it and leave it running, output to a log file.
        detached: bool,
        /// Keep the output in the data directory under this name.
        save_as: Option<&'static str>,
    },
    /// Wait until the node at `url` answers.
    WaitRpc { url: String },
    /// Point this machine's saved settings at a node on this machine.
    SaveLocalConfig,
}

/// What must happen before a step runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Free,
    /// The person types this word first. Used for steps that change the
    /// hardware key store or move funds.
    Typed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub id: &'static str,
    pub title: String,
    pub what: String,
    pub why: String,
    pub action: Action,
    pub gate: Gate,
    pub skippable: bool,
    /// Commands for the person to run elsewhere (another terminal, another
    /// machine). Shown exactly; marking the step done is their word.
    pub manual: Vec<String>,
    /// A limit or a part this program cannot do.
    pub caution: Option<String>,
}

impl Step {
    fn info(id: &'static str, title: &str, what: String, why: &str) -> Self {
        Self {
            id,
            title: title.into(),
            what,
            why: why.into(),
            action: Action::None,
            gate: Gate::Free,
            skippable: false,
            manual: Vec::new(),
            caution: None,
        }
    }

    fn exec(id: &'static str, title: &str, what: String, why: &str, prog: Prog, args: &[&str]) -> Self {
        let mut s = Self::info(id, title, what, why);
        s.action = Action::Exec {
            prog,
            args: args.iter().map(|a| a.to_string()).collect(),
            detached: false,
            save_as: None,
        };
        s
    }

    fn skip(mut self) -> Self {
        self.skippable = true;
        self
    }

    fn typed(mut self, word: &'static str) -> Self {
        self.gate = Gate::Typed(word);
        self
    }

    fn manual(mut self, lines: &[String]) -> Self {
        self.manual = lines.to_vec();
        self
    }

    fn caution(mut self, text: &str) -> Self {
        self.caution = Some(text.into());
        self
    }

    /// The command line shown to the person, exactly as run.
    pub fn command_line(&self) -> Option<String> {
        match &self.action {
            Action::Exec { prog, args, .. } => Some(display_command(prog.name(), args)),
            _ => None,
        }
    }
}

/// `program arg arg`, quoting arguments that need it.
pub fn display_command(prog: &str, args: &[String]) -> String {
    let mut s = prog.to_string();
    for a in args {
        s.push(' ');
        if a.is_empty() || a.chars().any(|c| c.is_whitespace() || "\"'$`\\".contains(c)) {
            s.push('"');
            s.push_str(&a.replace('"', "\\\""));
            s.push('"');
        } else {
            s.push_str(a);
        }
    }
    s
}

/// Where a person goes when a path cannot work here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    SwitchTo(Path),
    /// Keep the keys in another machine's TPM.
    Delegate,
    /// Nothing more can be done on this machine yet: save the settings and
    /// open the console, so the first run ends instead of looping.
    Finish,
}

impl Offer {
    pub fn label(&self) -> String {
        match self {
            Offer::SwitchTo(p) => format!("{}: {}", p.label(), p.blurb()),
            Offer::Delegate => "Keep this node's keys in another machine's TPM (a key holder)".into(),
            Offer::Finish => "Finish for now: open the console (run tenzro setup again when the network is announced)".into(),
        }
    }
}

/// Why a path cannot go on, in what/why/fix form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub what: String,
    pub why: String,
    pub fix: Vec<String>,
    pub offers: Vec<Offer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub path: Path,
    pub steps: Vec<Step>,
    pub blocked: Option<Blocked>,
    /// The one command to run next, shown last.
    pub next: String,
}

/// The person's choices and defaults that shape the commands.
#[derive(Debug, Clone)]
pub struct Opts {
    pub delegated: bool,
    pub name: String,
    pub machine_name: String,
    pub rpc: String,
    pub data_dir: PathBuf,
    pub holder_socket: String,
    pub holder_label: String,
}

impl Opts {
    pub fn defaults(m: &Machine, rpc: &str) -> Self {
        let machine_name = sanitize_machine_name(&m.hostname);
        let data_dir = tenzro_types::paths::default_data_dir();
        Self {
            delegated: false,
            name: m.hostname.clone(),
            holder_label: machine_name.clone(),
            machine_name,
            rpc: rpc.to_string(),
            holder_socket: data_dir.join("holder").join("h.sock").display().to_string(),
            data_dir,
        }
    }
}

/// A legal machine name from any hostname: 3 to 63 of `[a-z0-9-]`, not
/// starting or ending with a hyphen.
pub fn sanitize_machine_name(host: &str) -> String {
    let mapped: String = host
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let mut name = mapped.trim_matches('-').to_string();
    while name.contains("--") {
        name = name.replace("--", "-");
    }
    if name.len() < 3 {
        name = format!("tenzro-{name}").trim_matches('-').to_string();
    }
    name.truncate(63);
    name.trim_matches('-').to_string()
}

fn blocked(what: &str, why: &str, fix: &[&str], offers: Vec<Offer>, path: Path) -> Plan {
    Plan {
        path,
        steps: Vec::new(),
        blocked: Some(Blocked {
            what: what.into(),
            why: why.into(),
            fix: fix.iter().map(|s| s.to_string()).collect(),
            offers,
        }),
        next: "tenzro".into(),
    }
}

fn setup_args(mode: &str, operator: &str, o: &Opts) -> Vec<String> {
    let mut a: Vec<String> = [
        "setup", "--yes", "--path", "network", "--mode", mode, "--operator", operator,
        "--visibility", "private", "--name", &o.name, "--machine-name", &o.machine_name,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if o.rpc != crate::endpoint::PUBLIC_RPC {
        a.push("--rpc".into());
        a.push(o.rpc.clone());
    }
    a
}

/// The hardware-key steps for a path that needs a node's keys.
fn key_steps(m: &Machine, o: &Opts) -> Result<Vec<Step>, Box<Plan>> {
    let mut v = Vec::new();
    let path = Path::Validate;
    if o.delegated {
        if cfg!(windows) {
            return Err(Box::new(blocked(
                "A key holder cannot run on Windows.",
                "It talks to the other machine's TPM over a Unix socket, which Windows does not have.",
                &["Use a machine with its own TPM 2.0, or a Linux or macOS machine as the key holder."],
                vec![],
                path,
            )));
        }
        v.extend(holder_steps(o));
        return Ok(v);
    }
    match &m.root {
        KeyRoot::SecureEnclave => v.push(Step::info(
            "hardware-key",
            "Hardware key",
            "This Mac keeps the node's keys in its Secure Enclave. There is nothing to create.".into(),
            "Keys in hardware cannot be copied off the machine, so a stolen disk or backup holds no keys.",
        )),
        KeyRoot::TpmReady => v.push(Step::info(
            "hardware-key",
            "Hardware key",
            "This machine's TPM already holds the Tenzro keys. There is nothing to create.".into(),
            "Keys in hardware cannot be copied off the machine, so a stolen disk or backup holds no keys.",
        )),
        KeyRoot::TpmNeedsProvision | KeyRoot::TpmUnknown => {
            let mut before = Step::exec(
                "tpm-precheck",
                "Look at the TPM first",
                "Read-only: list the keys the TPM already holds and keep the list.".into(),
                "So you can see afterwards that provisioning only added the three Tenzro keys, and nothing else changed.",
                Prog::Other("tpm2_getcap"),
                &["handles-persistent"],
            )
            .skip();
            if let Action::Exec { save_as, .. } = &mut before.action {
                *save_as = Some("tpm-handles-before.txt");
            }
            v.push(before);
            v.push(
                Step::exec(
                    "tpm-provision",
                    "Create this machine's keys in the TPM",
                    "Creates three keys inside the TPM: a storage root, an attestation key and the node identity key. It is done once per machine; running it again keeps the keys already there.".into(),
                    "The node signs with these keys and refuses to start without them. They never leave the chip. It only adds keys; it never clears the TPM or touches other keys.",
                    Prog::Node,
                    &["tpm", "provision"],
                )
                .typed("provision")
                .caution("This changes the TPM. Close other programs that use it first."),
            );
        }
        KeyRoot::TpmNoAccess { reason, in_tss } => {
            return Err(Box::new(blocked(
                "This user cannot open the TPM.",
                &format!("The device exists but opening it failed: {reason}"),
                if *in_tss {
                    &["You are in the tss group already; check the device: ls -l /dev/tpmrm0 (group tss, mode 0660)."]
                } else {
                    &["sudo usermod -aG tss $USER, then log out and in again, then run tenzro."]
                },
                vec![Offer::Delegate],
                path,
            )));
        }
        KeyRoot::NoTpm => {
            return Err(Box::new(blocked(
                "This machine has no TPM 2.0.",
                "A node keeps its keys in hardware and there is none to use here.",
                &[
                    "If the machine has one, turn it on in the firmware settings (fTPM, PTT or Security Device) and reboot.",
                    "Or keep the keys in another machine's TPM with a key holder (limits are shown before you start).",
                ],
                vec![Offer::Delegate, Offer::SwitchTo(Path::UseNetwork)],
                path,
            )));
        }
        KeyRoot::NoSecureEnclave => {
            return Err(Box::new(blocked(
                "This Mac has no usable Secure Enclave.",
                "A node keeps its keys in hardware and there is none to use here.",
                &["Use a Mac with Apple silicon or a T2 chip, or a machine with a TPM 2.0."],
                vec![Offer::SwitchTo(Path::UseNetwork)],
                path,
            )));
        }
    }
    Ok(v)
}

/// The delegated key-holder steps (the runbook's key holder and grant).
fn holder_steps(o: &Opts) -> Vec<Step> {
    let sock = &o.holder_socket;
    let label = &o.holder_label;
    let mut v = Vec::new();
    v.push(
        Step::info(
            "holder-about",
            "Keep the keys in another machine's TPM",
            "This machine has no TPM, so a machine that has one (the provider) holds this node's keys and signs for it when asked. This machine runs a key holder that carries the requests.".into(),
            "It lets a Raspberry Pi or a TPM-less server run a node without keeping keys on its own disk.",
        )
        .caution(
            "Limits: Linux and macOS only (a Unix socket). The permission (a grant) is held in memory, lasts at most the provider's max_grant_hours (720 hours, 30 days) and is lost whenever the key holder restarts or this machine reboots. Without a valid grant the node cannot sign: for consensus it is down. Only the operator's passkey can renew it.",
        ),
    );
    v.push(
        Step::info(
            "holder-start",
            "Start the key holder",
            "Run this in another terminal or as a service. It makes a transport key in memory at every start and keeps running.".into(),
            "The node talks to the key holder over the socket; the key holder talks to the provider.",
        )
        .manual(&[format!(
            "tenzro-node tpm key-holder --socket {sock} --provider <PROVIDER-ENDPOINT>@<ADDRESS:PORT>"
        )]),
    );
    v.push(
        Step::info(
            "holder-request",
            "Ask for a grant",
            "Prints the endpoint, the end time and a challenge that the operator's passkey must sign.".into(),
            "A grant is the operator's permission, signed by their passkey, for this machine to use the provider's TPM until the end time.",
        )
        .manual(&[format!(
            "tenzro-node tpm grant-request --socket {sock} --label {label} --valid-hours 720"
        )]),
    );
    v.push(
        Step::info(
            "holder-passkey",
            "PASSKEY ASSERTION (done outside this program)",
            "The operator's passkey signs the challenge printed above. That produces four values: credential id, authenticator data, client data JSON and signature.".into(),
            "Only a person holding the passkey can grant the permission; this program never sees the passkey.",
        )
        .caution("This program cannot produce the assertion. It needs a page or tool that asks the passkey to sign the challenge and prints the four values. Do this step on a machine where that works, then continue."),
    );
    v.push(
        Step::info(
            "holder-install",
            "Install the grant",
            "Give the key holder the four signed values and the end time exactly as grant-request printed them.".into(),
            "Now the key holder may use the provider. Repeat steps 3 to 5 after every key holder restart and before the end time.",
        )
        .manual(&[format!(
            "tenzro-node tpm grant-install --socket {sock} --label {label} --not-after-ms <as printed> --credential-id <..> --authenticator-data <..> --client-data-json <..> --signature <..>"
        )]),
    );
    v.push(
        Step::exec(
            "holder-check",
            "Check the key holder works",
            "Asks the provider to sign something through the key holder. It fails when the grant is missing or over.".into(),
            "Proves the whole chain (node, key holder, provider, TPM) before the node depends on it.",
            Prog::Node,
            &["tpm", "remote-check", "--key-holder", sock, "--label", label],
        )
        .skip(),
    );
    v
}

fn node_ready(m: &Machine, path: Path) -> Result<(), Box<Plan>> {
    match (&m.node_binary, &m.node_build) {
        (None, _) => Err(Box::new(blocked(
            "The node program is missing.",
            "tenzro-node was not found next to tenzro or on PATH.",
            &["Install the Tenzro package for this machine (it puts tenzro and tenzro-node together), then run tenzro again."],
            vec![],
            path,
        ))),
        (Some(_), Some(b)) if !b.startup_ok => {
            let why = b.refusal.clone().unwrap_or_else(|| "its hardware check refused".into());
            let gpu_cpu = !m.gpus.is_empty() && b.flavour.to_lowercase().contains("cpu");
            Err(Box::new(blocked(
                "This build of the node would refuse to start on this machine.",
                &if gpu_cpu {
                    format!("It is the CPU build and this machine has a GPU ({}). {why}", m.gpus[0])
                } else {
                    why
                },
                &["Install the package that matches this machine: the CUDA package on an NVIDIA GPU machine, the CPU package otherwise."],
                vec![],
                path,
            )))
        }
        _ => Ok(()),
    }
}

/// Plan the steps of `path`. Pure.
pub fn plan(path: Path, m: &Machine, net: &Net, o: &Opts) -> Plan {
    match path {
        Path::UseNetwork => plan_use(m, net, o),
        Path::Provide => plan_serve(Path::Provide, m, net, o),
        Path::Validate => plan_serve(Path::Validate, m, net, o),
        Path::Local => plan_local(m, o),
    }
}

fn network_down(path: Path, net: &Net, o: &Opts) -> Option<Plan> {
    if net.is_reachable() {
        return None;
    }
    let why = match net {
        Net::NotResolving => format!(
            "The name {} does not resolve yet, so the public network is not reachable at this address.",
            crate::friendly::host_of(&o.rpc)
        ),
        Net::NotAnswering { reason } => format!("{} did not answer: {reason}", o.rpc),
        _ => "The network check has not finished.".into(),
    };
    Some(blocked(
        "The network is not reachable yet.",
        &why,
        &["Come back and run tenzro again when the network is announced.", "Meanwhile you can try Tenzro on this machine: it runs its own local chain."],
        vec![Offer::SwitchTo(Path::Local), Offer::Finish],
        path,
    ))
}

fn plan_use(m: &Machine, net: &Net, o: &Opts) -> Plan {
    if let Some(b) = network_down(Path::UseNetwork, net, o) {
        return b;
    }
    let _ = m;
    let steps = vec![
        Step::info(
            "about",
            "What happens",
            "A wallet and identity are created for you on the network. You approve them with a passkey in your browser (a phone works too).".into(),
            "The passkey, not a password, controls your account. Nothing secret is stored by this program.",
        ),
        Step::exec(
            "setup",
            "Create your identity and wallet",
            "Runs the same setup as `tenzro setup`, with these answers filled in.".into(),
            "It opens your browser for the passkey and saves your settings.",
            Prog::Cli,
            &setup_args("consume", "self", o).iter().map(String::as_str).collect::<Vec<_>>(),
        ),
    ];
    Plan { path: Path::UseNetwork, steps, blocked: None, next: "tenzro".into() }
}

fn plan_serve(path: Path, m: &Machine, net: &Net, o: &Opts) -> Plan {
    if let Some(b) = network_down(path, net, o) {
        return b;
    }
    if let Err(b) = node_ready(m, path) {
        return *b;
    }
    let keys = match key_steps(m, o) {
        Ok(k) => k,
        Err(mut b) => {
            b.path = path;
            return *b;
        }
    };
    let validate = path == Path::Validate;
    let roles = if validate { "validator" } else { "ai" };
    let mut steps = Vec::new();
    steps.push(Step::info(
        "hardware",
        "This machine",
        format!(
            "{} cores, {:.0} GB memory, {:.0} GB free disk{}.",
            m.cores,
            m.ram_gb,
            m.disk_free_gb,
            if m.gpus.is_empty() { ", no GPU".to_string() } else { format!(", {}", m.gpus.join(", ")) }
        ),
        if validate {
            "A validator needs a hardware key and a node that stays up; a GPU is not needed."
        } else {
            "Serving models needs memory and ideally a GPU; the node picks what fits."
        },
    ));
    steps.extend(keys);
    let operator = if o.delegated || !m.root.has_local_hardware() { "self" } else { "autonomous" };
    steps.push(Step::exec(
        "setup",
        "Save your setup",
        "Runs the same setup as `tenzro setup` for this role: machine name, reachability, identity, roles. It writes your settings and a service unit file; it does not start anything.".into(),
        "The node and the later steps read these settings.",
        Prog::Cli,
        &setup_args(if validate { "validate" } else { "provide" }, operator, o).iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    let mut start_args = vec!["--roles".to_string(), roles.to_string(), "--data-dir".to_string(), o.data_dir.display().to_string()];
    if o.delegated {
        start_args.extend(["--tpm-key-holder".into(), o.holder_socket.clone(), "--tpm-label".into(), o.holder_label.clone()]);
    }
    let mut start = Step::info(
        "start-node",
        "Start the node",
        format!("Starts tenzro-node with the {roles} role in the background and writes its log next to its data."),
        "The node syncs the chain and serves its role. You join as a verify-only node first; that is normal. It may sit at block 0 on a quiet chain until the next block.",
    );
    start.action = Action::Exec { prog: Prog::Node, args: start_args, detached: true, save_as: None };
    steps.push(start);
    steps.push(Step {
        id: "wait-node",
        title: "Wait for the node".into(),
        what: "Waits until the node answers on this machine.".into(),
        why: "Registering and bonding need the node running.".into(),
        action: Action::WaitRpc { url: crate::endpoint::LOCAL_RPC.into() },
        gate: Gate::Free,
        skippable: true,
        manual: vec![],
        caution: None,
    });
    if validate {
        steps.push(
            Step::info(
                "admission",
                "Admission needs approval",
                "During the preview a new validator is admitted by governance: an ApproveValidators proposal must name your account before you can register. Ask for approval with the operator request form at https://tenzro.com/join.".into(),
                "It keeps the early validator set small and known. Everything else (syncing, following the chain) works without approval.",
            )
            .manual(&[
                "tenzro validator keys --stake 10000".to_string(),
                "tenzro sponsor status".to_string(),
                "tenzro validator get <your account address>".to_string(),
            ])
            .caution("Those commands check your status: your keys to put in the form, the sponsorship state, and whether your account is on the validator list."),
        );
        // Registration is the node registering itself: it boots with
        // --validator-self-stake and registers with its own keys once the
        // account holds the stake plus gas (the same thing `tenzro setup
        // --mode validate` writes into its unit). `tenzro validator register`
        // takes eight pasted key arguments and is the manual route.
        let mut args = vec!["--roles".to_string(), "validator".to_string(), "--data-dir".to_string(), o.data_dir.display().to_string()];
        if o.delegated {
            args.extend(["--tpm-key-holder".into(), o.holder_socket.clone(), "--tpm-label".into(), o.holder_label.clone()]);
        }
        args.extend(["--validator-self-stake".into(), "10000000000000000000000".into()]);
        let mut reg = Step::info(
            "register",
            "Stake and register as a validator",
            "Restarts your node with a self-stake of 10,000 TNZO (10000000000000000000000 wei). The node then registers itself with its own keys once the account holds the stake plus a little for fees, and has been approved.".into(),
            "The stake is what makes your votes count and is what you can lose if the node misbehaves.",
        )
        .skip()
        .typed("stake")
        .manual(&["tenzro-node graceful-exit   (stops the verify-only node first)".to_string()]);
        reg.action = Action::Exec { prog: Prog::Node, args, detached: true, save_as: None };
        reg.caution = Some("This moves funds. Stop the running node with the command above first. Skip it now if you are not approved yet or the account is not funded; do it later with the same command.".into());
        steps.push(reg);
    } else {
        steps.push(
            Step::info(
                "bond",
                "Bond and go live",
                "Providing compute posts a bond from your wallet and registers your models. Setup handled the registration; the bond needs TNZO in your wallet.".into(),
                "The bond is what a buyer is protected by if a provider fails to deliver.",
            )
            .manual(&["tenzro provider status".to_string(), "tenzro join --provider".to_string()])
            .caution("There is no faucet. Fund the wallet, or ask for sponsorship with the operator request form at https://tenzro.com/join, then run `tenzro join --provider`."),
        );
    }
    let mut leave = Step::info(
        "leave",
        "How to leave",
        if validate {
            "To stop being a validator: tenzro validator exit. To stop the node cleanly: tenzro-node graceful-exit (it waits until it leads no coming round, then shuts down).".into()
        } else {
            "To stop the node cleanly: tenzro-node graceful-exit (it waits until it leads no coming round, then shuts down).".into()
        },
        "Stopping cleanly avoids missed rounds. Leaving the set is a transaction, and unstaking takes the unbonding period.",
    );
    leave.manual = if validate {
        vec!["tenzro validator exit".into(), "tenzro-node graceful-exit".into()]
    } else {
        vec!["tenzro-node graceful-exit".into()]
    };
    steps.push(leave);
    Plan { path, steps, blocked: None, next: "tenzro".into() }
}

fn plan_local(m: &Machine, o: &Opts) -> Plan {
    if let Err(b) = node_ready(m, Path::Local) {
        return *b;
    }
    let keys = match key_steps(m, &Opts { delegated: false, ..o.clone() }) {
        Ok(k) => k,
        Err(mut b) => {
            if let Some(bl) = b.blocked.as_mut() {
                bl.offers.retain(|x| *x != Offer::Delegate);
                bl.offers.push(Offer::Finish);
            }
            b.path = Path::Local;
            return *b;
        }
    };
    let mut steps = vec![Step::info(
        "about",
        "What happens",
        "A private chain with one validator runs on this machine, with a funded account for you. Nothing leaves the machine and no stake is needed.".into(),
        "It is the quickest way to learn Tenzro and to build against it.",
    )];
    steps.extend(keys);
    steps.push(Step {
        id: "save",
        title: "Save the setting".into(),
        what: format!("Points tenzro at the chain on this machine ({}).", crate::endpoint::LOCAL_RPC),
        why: "So the console and every command talk to your local chain.".into(),
        action: Action::SaveLocalConfig,
        gate: Gate::Free,
        skippable: false,
        manual: vec![],
        caution: None,
    });
    Plan { path: Path::Local, steps, blocked: None, next: "tenzro dev".into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::detect::NodeBuild;

    fn machine(root: KeyRoot) -> Machine {
        let mut m = Machine::blank();
        m.root = root;
        m.node_binary = Some(PathBuf::from("/usr/bin/tenzro-node"));
        m.node_build = Some(NodeBuild { flavour: "cpu".into(), startup_ok: true, refusal: None });
        m
    }

    fn up() -> Net {
        Net::Reachable { chain_id: "0x1".into() }
    }

    fn opts(m: &Machine) -> Opts {
        Opts::defaults(m, crate::endpoint::PUBLIC_RPC)
    }

    fn ids(p: &Plan) -> Vec<&'static str> {
        p.steps.iter().map(|s| s.id).collect()
    }

    #[test]
    fn using_the_network_needs_no_hardware_and_one_command() {
        let m = machine(KeyRoot::NoTpm);
        let p = plan(Path::UseNetwork, &m, &up(), &opts(&m));
        assert!(p.blocked.is_none());
        let cmd = p.steps.last().unwrap().command_line().unwrap();
        assert!(cmd.starts_with("tenzro setup --yes --path network --mode consume"));
        assert_eq!(p.next, "tenzro");
    }

    #[test]
    fn with_the_network_down_every_network_path_is_blocked_and_offers_local() {
        let m = machine(KeyRoot::TpmReady);
        for path in [Path::UseNetwork, Path::Provide, Path::Validate] {
            let p = plan(path, &m, &Net::NotResolving, &opts(&m));
            let b = p.blocked.expect("blocked");
            assert!(b.why.contains("does not resolve"));
            assert_eq!(b.offers, vec![Offer::SwitchTo(Path::Local), Offer::Finish]);
        }
    }

    #[test]
    fn the_local_chain_works_with_the_network_down_and_ends_with_tenzro_dev() {
        let m = machine(KeyRoot::TpmReady);
        let p = plan(Path::Local, &m, &Net::NotResolving, &opts(&m));
        assert!(p.blocked.is_none());
        assert_eq!(p.next, "tenzro dev");
        assert!(ids(&p).contains(&"save"));
    }

    #[test]
    fn a_machine_without_a_tpm_is_told_plainly_and_can_delegate() {
        let m = machine(KeyRoot::NoTpm);
        let p = plan(Path::Validate, &m, &up(), &opts(&m));
        let b = p.blocked.unwrap();
        assert!(b.what.contains("no TPM"));
        assert!(b.offers.contains(&Offer::Delegate));
        let local = plan(Path::Local, &m, &up(), &opts(&m)).blocked.unwrap();
        assert!(!local.offers.contains(&Offer::Delegate));
    }

    #[test]
    fn provisioning_the_tpm_needs_a_typed_word_and_is_preceded_by_a_read_only_look() {
        let m = machine(KeyRoot::TpmNeedsProvision);
        let p = plan(Path::Validate, &m, &up(), &opts(&m));
        let order = ids(&p);
        let pre = order.iter().position(|i| *i == "tpm-precheck").unwrap();
        let prov = order.iter().position(|i| *i == "tpm-provision").unwrap();
        assert!(pre < prov);
        let s = &p.steps[prov];
        assert_eq!(s.gate, Gate::Typed("provision"));
        assert_eq!(s.command_line().unwrap(), "tenzro-node tpm provision");
        assert!(!s.skippable);
        assert!(p.steps[pre].skippable);
    }

    #[test]
    fn staking_needs_a_typed_word_and_can_be_skipped_safely() {
        let m = machine(KeyRoot::TpmReady);
        let p = plan(Path::Validate, &m, &up(), &opts(&m));
        let reg = p.steps.iter().find(|s| s.id == "register").unwrap();
        assert_eq!(reg.gate, Gate::Typed("stake"));
        assert!(reg.command_line().unwrap().contains("--validator-self-stake 10000000000000000000000"));
        assert!(reg.skippable);
        let order = ids(&p);
        let adm = order.iter().position(|i| *i == "admission").unwrap();
        let reg_i = order.iter().position(|i| *i == "register").unwrap();
        assert!(adm < reg_i, "approval is explained before staking");
        let admission = &p.steps[adm];
        assert!(admission.what.contains("tenzro.com/join"));
        assert!(admission.what.contains("governance"));
    }

    #[test]
    fn the_validator_path_runs_in_the_runbook_order() {
        let m = machine(KeyRoot::TpmNeedsProvision);
        let p = plan(Path::Validate, &m, &up(), &opts(&m));
        assert_eq!(
            ids(&p),
            ["hardware", "tpm-precheck", "tpm-provision", "setup", "start-node", "wait-node", "admission", "register", "leave"]
        );
    }

    #[test]
    fn delegation_marks_the_passkey_step_and_the_limits_and_passes_the_holder_to_the_node() {
        let m = machine(KeyRoot::NoTpm);
        let mut o = opts(&m);
        o.delegated = true;
        let p = plan(Path::Validate, &m, &up(), &o);
        if cfg!(windows) {
            assert!(p.blocked.is_some());
            return;
        }
        let pk = p.steps.iter().find(|s| s.id == "holder-passkey").unwrap();
        assert!(pk.title.contains("PASSKEY ASSERTION"));
        assert!(pk.caution.as_ref().unwrap().contains("cannot produce"));
        let about = p.steps.iter().find(|s| s.id == "holder-about").unwrap();
        assert!(about.caution.as_ref().unwrap().contains("720"));
        let start = p.steps.iter().find(|s| s.id == "start-node").unwrap();
        let cmd = start.command_line().unwrap();
        assert!(cmd.contains("--tpm-key-holder") && cmd.contains("--tpm-label"));
        assert!(p.steps.iter().find(|s| s.id == "setup").unwrap().command_line().unwrap().contains("--operator self"));
    }

    #[test]
    fn a_cpu_build_on_a_gpu_machine_blocks_with_the_fix() {
        let mut m = machine(KeyRoot::TpmReady);
        m.gpus = vec!["NVIDIA GPU".into()];
        m.node_build = Some(NodeBuild { flavour: "cpu".into(), startup_ok: false, refusal: Some("refused".into()) });
        let b = plan(Path::Provide, &m, &up(), &opts(&m)).blocked.unwrap();
        assert!(b.why.contains("CPU build"));
        assert!(b.fix[0].contains("CUDA"));
    }

    #[test]
    fn a_missing_node_program_blocks_with_what_why_fix() {
        let mut m = machine(KeyRoot::TpmReady);
        m.node_binary = None;
        let b = plan(Path::Validate, &m, &up(), &opts(&m)).blocked.unwrap();
        assert!(!b.what.is_empty() && !b.why.is_empty() && !b.fix.is_empty());
    }

    #[test]
    fn machine_names_are_always_legal() {
        for (host, ok) in [("My Laptop.local", "my-laptop-local"), ("PC", "tenzro-pc"), ("-a-", "tenzro-a"), ("srv_01", "srv-01")] {
            let n = sanitize_machine_name(host);
            assert_eq!(n, ok, "{host}");
            assert!(n.len() >= 3 && n.len() <= 63 && !n.starts_with('-') && !n.ends_with('-'));
        }
        assert!(sanitize_machine_name(&"a".repeat(100)).len() <= 63);
    }
}
