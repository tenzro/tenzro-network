//! `tenzro control`: the local helper the Tenzro Control apps talk to.
//!
//! It speaks JSON-RPC, one message per line, on a socket only the user who
//! started it can open. Methods named `control_*` are answered here, so they
//! work while the node is stopped or not installed.
//!
//! With `--web` it serves the web console instead: the page's files and the
//! same calls over HTTP, on an address only this machine can reach, for the
//! one page that opened the link the command printed.
//!
//! # Who can ask, and what asking grants
//!
//! The socket admits one user: the one who started the helper. It cannot tell
//! that user's programs apart, so every program running as that user can open
//! it, and opening it is all the sign-in there is. What any `control_` call
//! reads or changes, the conditions waiting for the operator among it, every
//! such program may. The console is the other way in: it answers the one
//! page that handed in the ticket from the link the command printed, and that
//! page may make the same calls.
//!
//! A caller gets the helper's own methods and the node's reads named in
//! `NODE_READS`. Those reads go to the node with the user's signed-in session
//! and a fresh proof of it, so a caller reads what the operator may read, and
//! the node's answer comes back unchanged. Every other method of the node is
//! refused here and never reaches it: naming the node's method for it does not
//! stop the node, install a release, move stake, change a role, change who may
//! use the node or remove a device.
//!
//! The session travels with each read, so the node has to be this machine's:
//! an address that is not loopback is refused unless `--remote-node` says the
//! operator means it.
//!
//! With `--web` there is no socket: the console answers the one page that
//! opened the link, and that page gets what the socket grants and no more.

mod ceremony;
mod checklist;
mod conditions;
mod decide;
mod devices;
mod identity;
mod key_holders;
mod node_service;
mod pairing;
mod server;
mod settings;
mod setup;
mod signed;
mod summary;
mod update;
mod web;

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::Parser;
use serde_json::{Value, json};

use crate::rpc::RpcClient;
use crate::tui::detect::{KeyRoot, key_root};
use ceremony::Ceremonies;
use key_holders::KeyHolders;
use node_service::Service;
use settings::Settings;
use setup::Setup;
use summary::{Local, Reads};
use update::Updates;

/// Serve this machine's node and its setup to the Tenzro Control apps
///
/// Only the user who starts the helper can open its socket, and every program
/// that user runs can. A program that opens it gets the helper's own calls and
/// the reads of this machine's node the helper passes on, which are sent with
/// that user's signed-in session. Every other call to the node is refused.
#[derive(Debug, Parser)]
pub struct ControlCmd {
    /// This machine's node
    #[arg(long, value_name = "URL", default_value = crate::endpoint::LOCAL_RPC)]
    node: String,

    /// Send this user's signed-in session to a node that is not on this machine
    #[arg(long)]
    remote_node: bool,

    /// Listen here instead of the usual place
    #[arg(long, env = "TENZRO_CONTROL_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Serve the web console instead of the socket, to this machine only: from DIR, or from where a release install keeps it
    #[arg(long, value_name = "DIR", num_args = 0..=1)]
    web: Option<Option<PathBuf>>,

    /// The web console's port on this machine
    #[arg(long, value_name = "PORT", default_value_t = 8765, requires = "web")]
    web_port: u16,
}

impl ControlCmd {
    pub async fn execute(&self) -> Result<()> {
        if !self.remote_node && !on_this_machine(&self.node) {
            bail!(
                "{} is not on this machine. The helper sends this user's signed-in session to \
                 its node; pass --remote-node if that is where it should go.",
                self.node
            );
        }
        let helper = Arc::new(Helper {
            node: RpcClient::only_at(&self.node),
            node_wait: NODE_ANSWER_WAIT,
            local: Box::new(|node_answers| Box::pin(read_machine(node_answers))),
            setup: Setup::here(),
            ceremonies: Ceremonies::here(&self.node),
            updates: Updates::here(&self.node),
            settings: Settings::here(),
            service: Service::here(),
            key_holders: KeyHolders::here(),
        });
        match &self.web {
            Some(files) => {
                let files = match files {
                    Some(dir) => dir.clone(),
                    None => web::installed_console()?,
                };
                web::run(&files, self.web_port, helper).await
            }
            None => {
                let at = self.socket.clone().unwrap_or_else(server::default_socket);
                server::run(&at, helper).await
            }
        }
    }
}

/// Whether `node` is an address on this machine.
fn on_this_machine(node: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(node) else {
        return false;
    };
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

/// How long the node has to answer one call, or every read one summary makes,
/// before the helper calls it silent.
const NODE_ANSWER_WAIT: Duration = Duration::from_secs(5);

/// How long a reading of where this machine's keys are stands.
const KEYS_READING_STANDS: Duration = Duration::from_secs(30);

/// How long a reading of whether a node process runs stands.
const PROCESS_READING_STANDS: Duration = Duration::from_secs(3);

/// A JSON-RPC error the helper raises itself.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const REFUSED: i64 = -32000;
/// What was asked names something the helper does not have.
const INVALID_PARAMS: i64 = -32602;

/// The node's methods a caller reaches through the helper, sorted. Each is a
/// read: none changes the node, its chain state or this machine.
const NODE_READS: &[&str] = &[
    "tenzro_getConnectivity",
    "tenzro_getNodeStatus",
    "tenzro_getRole",
    "tenzro_getRoleStakes",
    "tenzro_getUpdateNotice",
    "tenzro_nodeProfile",
    "tenzro_queryEvents",
    "tenzro_syncing",
    "web3_clientVersion",
];

/// Reads what only this machine knows; told whether the node answered, which
/// spares the checks that matter only while it is silent.
type LocalSource = Box<dyn Fn(bool) -> Pin<Box<dyn Future<Output = Local> + Send>> + Send + Sync>;

/// The helper: this machine's node, this machine, its setup, the passkey
/// ceremonies it started, the updates of its release, its settings, its
/// node service and its key holder.
pub(crate) struct Helper {
    node: RpcClient,
    /// How long the node has to answer one call, or every read of one summary.
    node_wait: Duration,
    local: LocalSource,
    setup: Arc<Setup>,
    ceremonies: Arc<Ceremonies>,
    updates: Arc<Updates>,
    settings: Settings,
    service: Service,
    key_holders: KeyHolders,
}

impl Helper {
    /// Answers one request line with one response line. A message without an
    /// id asks for no answer: it gets none, and nothing is run for it.
    pub(crate) async fn answer(&self, line: &[u8]) -> Option<String> {
        let Ok(request) = serde_json::from_slice::<Value>(line) else {
            return Some(unasked(PARSE_ERROR, "the request is not JSON"));
        };
        let Some(request) = request.as_object() else {
            return Some(unasked(INVALID_REQUEST, "the request is not an object"));
        };
        let id = request.get("id")?.clone();
        let outcome = match request.get("method").and_then(Value::as_str) {
            Some(method) => {
                let params = request.get("params").cloned().unwrap_or(Value::Null);
                self.dispatch(method, params).await
            }
            None => Err(error(INVALID_REQUEST, "the request names no method")),
        };
        Some(response(id, outcome))
    }

    /// The helper's own methods are answered here. Of the node's, the reads in
    /// `NODE_READS` are passed on and the rest are refused unasked.
    async fn dispatch(&self, method: &str, params: Value) -> std::result::Result<Value, Value> {
        match method {
            "control_summary" => Ok(self.summary().await),
            "control_setupPlan" => self.setup.plan(&params).await,
            "control_setupRun" => self.setup.run(&params).await,
            "control_setupSkip" => self.setup.skip(&params).await,
            "control_checklist" => Ok(checklist::checklist().await),
            "control_fix" => checklist::fix(&params).await,
            "control_ceremony" => self.ceremonies.start(&params).await,
            "control_ceremonyStatus" => self.ceremonies.status(&params),
            "control_identity" => Ok(self.identity().await),
            "control_update" => self.updates.call(&params).await,
            "control_settings" => Ok(self.settings.read().await),
            "control_setSettings" => self.settings.change(&params).await,
            "control_service" => self.serve(&params).await,
            "control_keyHolders" => self.key_holders.list().await,
            "control_useKeyHolder" => self.key_holders.choose(&params).await,
            "control_stake" => self.stake("stake", &params).await,
            "control_unstake" => self.stake("unstake", &params).await,
            "control_setRole" => self.set_role(&params).await,
            "control_bindDevice" => self.bind_device(&params).await,
            "control_revokeDevice" => self.revoke_device(&params).await,
            "control_listConditions" => self.list_conditions().await,
            "control_decide" => self.decide(&params).await,
            "control_pairDevice" => self.pair_device(&params).await,
            "control_listPairedDevices" => self.list_paired_devices().await,
            "control_unpairDevice" => self.unpair_device(&params).await,
            _ if method.starts_with("control_") => Err(error(METHOD_NOT_FOUND, "Method not found")),
            _ if NODE_READS.binary_search(&method).is_ok() => self
                .ask_node(method, params, self.node_has_until())
                .await
                .unwrap_or_else(|| Err(error(REFUSED, "This machine's node is not answering."))),
            _ => Err(error(
                REFUSED,
                "The helper passes only reads to this machine's node, and this call is not one of them.",
            )),
        }
    }

    /// `control_service`: the action, then how the node stands.
    async fn serve(&self, params: &Value) -> Result<Value, Value> {
        let restart = params.get("action").and_then(Value::as_str) == Some("restart")
            && params.get("confirm").and_then(Value::as_str) == Some("restart");
        if restart && self.service.under_systemd().await {
            self.node_call("tenzro_restartNode", json!([])).await?;
            return Ok(json!({ "service": "running", "reason": null }));
        }
        self.service.act(params).await?;
        let local = (self.local)(false).await;
        Ok(json!({ "service": summary::service_state(&local), "reason": null }))
    }

    async fn summary(&self) -> Value {
        let until = self.node_has_until();
        let Some(status) = self
            .ask_node("tenzro_getNodeStatus", json!([]), until)
            .await
        else {
            return summary::compose(None, &(self.local)(false).await);
        };
        let status = status.ok();
        let (syncing, role, stakes, notice, conditions) = tokio::join!(
            self.read("tenzro_syncing", json!([]), until),
            self.read("tenzro_getRole", json!([]), until),
            self.read("tenzro_getRoleStakes", json!({}), until),
            self.read("tenzro_getUpdateNotice", json!([]), until),
            self.read("tenzro_listConditions", json!([]), until),
        );
        let balance = match summary::stake_address(status.as_ref(), stakes.as_ref()) {
            Some(address) => {
                self.read("eth_getBalance", json!([address, "latest"]), until)
                    .await
            }
            None => None,
        };
        let reads = Reads {
            status,
            syncing,
            role,
            stakes,
            notice,
            balance,
            conditions,
        };
        summary::compose(Some(&reads), &(self.local)(true).await)
    }

    /// The moment by which the node has to have answered what is asked now.
    fn node_has_until(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.node_wait
    }

    /// One read of the node: its result, or `None` when it gave none by `until`.
    async fn read(
        &self,
        method: &str,
        params: Value,
        until: tokio::time::Instant,
    ) -> Option<Value> {
        self.ask_node(method, params, until).await?.ok()
    }

    /// One call to the node: its result or its error as it sent it, or `None`
    /// when no answer came by `until`.
    async fn ask_node(
        &self,
        method: &str,
        params: Value,
        until: tokio::time::Instant,
    ) -> Option<std::result::Result<Value, Value>> {
        tokio::time::timeout_at(until, self.node.forward(method, params))
            .await
            .ok()?
            .ok()
    }
}

/// The response line for the request `id` names.
fn response(id: Value, outcome: std::result::Result<Value, Value>) -> String {
    match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    }
    .to_string()
}

fn error(code: i64, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

/// The response line for something that carried no id the helper could read.
fn unasked(code: i64, message: &str) -> String {
    response(Value::Null, Err(error(code, message)))
}

/// Reads this machine: its saved setup, whether a node is installed and
/// running, whether a key holder still wants its grant, and where its keys are.
async fn read_machine(node_answers: bool) -> Local {
    let config = crate::config::load_config();
    let holder = config.key_holder_socket.as_ref().map(PathBuf::from);
    let keys_in = match holder {
        Some(_) => "key_holder",
        None => keys_in().await,
    };
    let (node_process, node_installed, grant_wanted) = tokio::task::spawn_blocking(move || {
        if node_answers {
            return (true, true, None);
        }
        let running = node_process_runs();
        let grant_wanted = holder
            .filter(|_| running)
            .and_then(|socket| tenzro_device_key::remote::grant_wanted(&socket, now_ms()));
        let installed = running || crate::commands::setup::locate_node_binary().is_some();
        (running, installed, grant_wanted)
    })
    .await
    .unwrap_or((node_answers, node_answers, None));
    Local {
        node_process,
        node_installed,
        grant_wanted,
        keys_in,
        key_holder_label: config.key_holder_label,
        passkey_bound: config.authority.as_deref().map(|a| a == "passkey"),
        did: config.did,
        wallet_address: config.wallet_address,
    }
}

/// Where this machine holds keys itself, by the check setup runs; the reading
/// stands for a while, since taking it asks the hardware.
async fn keys_in() -> &'static str {
    static READING: Mutex<Option<(Instant, &'static str)>> = Mutex::new(None);
    if let Some((at, reading)) = *READING.lock().unwrap_or_else(|e| e.into_inner())
        && at.elapsed() < KEYS_READING_STANDS
    {
        return reading;
    }
    let hardware = crate::commands::hardware::detect_hardware_profile().await;
    let secure_enclave = crate::commands::setup::has_secure_enclave(&hardware);
    let reading = tokio::task::spawn_blocking(move || {
        match key_root(&crate::commands::preflight::Facts::probe(secure_enclave)) {
            KeyRoot::SecureEnclave => "secure_enclave",
            KeyRoot::TpmReady => "tpm",
            _ => "none",
        }
    })
    .await
    .unwrap_or("none");
    *READING.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), reading));
    reading
}

/// Whether a node process runs on this machine; the reading stands for a
/// moment, since taking it walks every process.
fn node_process_runs() -> bool {
    static READING: Mutex<Option<(Instant, bool)>> = Mutex::new(None);
    let mut reading = READING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, runs)) = *reading
        && at.elapsed() < PROCESS_READING_STANDS
    {
        return runs;
    }
    let system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::new()),
    );
    let runs = system
        .processes()
        .values()
        .any(|p| std::path::Path::new(p.name()).file_stem() == Some("tenzro-node".as_ref()));
    *reading = Some((Instant::now(), runs));
    runs
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// A directory only this user may write in, as the socket's must be.
    pub(super) fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let only_this_user = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(dir.path(), only_this_user).unwrap();
        }
        dir
    }

    pub(super) fn machine() -> Local {
        Local {
            node_process: false,
            node_installed: true,
            grant_wanted: None,
            keys_in: "tpm",
            key_holder_label: None,
            passkey_bound: Some(true),
            did: Some("did:tenzro:human:saved".into()),
            wallet_address: Some("0x00000000000000000000000000000000000000cc".into()),
        }
    }

    /// A helper for a test that asks nothing of setup and starts no ceremony;
    /// its progress is kept nowhere.
    pub(super) fn helper(node: &str, local: Local) -> Arc<Helper> {
        helper_waiting(node, local, NODE_ANSWER_WAIT)
    }

    fn helper_waiting(node: &str, local: Local, node_wait: Duration) -> Arc<Helper> {
        assembled(
            node,
            local,
            node_wait,
            setup::tests::ready(PathBuf::new()),
            no_ceremonies(node),
        )
    }

    fn helper_with(node: &str, local: Local, setup: Arc<Setup>) -> Arc<Helper> {
        assembled(node, local, NODE_ANSWER_WAIT, setup, no_ceremonies(node))
    }

    /// For a test that starts no ceremony; none would keep what it made.
    fn no_ceremonies(node: &str) -> Arc<Ceremonies> {
        ceremony::tests::kept_in(node, &PathBuf::new(), Duration::ZERO)
    }

    /// A helper whose ceremonies give their page `wait` and keep nothing.
    pub(super) fn helper_holding(node: &str, wait: Duration) -> Arc<Helper> {
        let ceremonies = ceremony::tests::kept_in(node, &PathBuf::new(), wait);
        let setup = setup::tests::ready(PathBuf::new());
        assembled(node, machine(), NODE_ANSWER_WAIT, setup, ceremonies)
    }

    /// A helper for a test that drives the node service `service`.
    pub(super) fn helper_serving(node: &str, service: Service) -> Arc<Helper> {
        let mut helper = built(
            node,
            machine(),
            NODE_ANSWER_WAIT,
            setup::tests::ready(PathBuf::new()),
            no_ceremonies(node),
        );
        helper.service = service;
        Arc::new(helper)
    }

    fn assembled(
        node: &str,
        local: Local,
        node_wait: Duration,
        setup: Arc<Setup>,
        ceremonies: Arc<Ceremonies>,
    ) -> Arc<Helper> {
        Arc::new(built(node, local, node_wait, setup, ceremonies))
    }

    fn built(
        node: &str,
        local: Local,
        node_wait: Duration,
        setup: Arc<Setup>,
        ceremonies: Arc<Ceremonies>,
    ) -> Helper {
        Helper {
            node: RpcClient::only_at(node),
            node_wait,
            local: Box::new(move |_| {
                let local = local.clone();
                Box::pin(async move { local })
            }),
            setup,
            ceremonies,
            updates: update::tests::idle(),
            service: node_service::tests::on(
                "linux",
                false,
                crate::commands::service::NodeService::None,
                Arc::default(),
            ),
            key_holders: key_holders::tests::kept_in(
                &std::env::temp_dir().join("tenzro-control-no-key-holders"),
                |_| key_holders::Heard {
                    answers: false,
                    wanted: None,
                },
            ),
            settings: settings::tests::kept_in(
                std::env::temp_dir().join("tenzro-control-no-settings"),
                None,
            ),
        }
    }

    /// An address on this machine that nothing listens on.
    fn silent_node() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    }

    /// Serves `helper` at a fresh place and returns it; the directory keeps a
    /// socket's place alive for the test.
    fn listening(helper: Arc<Helper>) -> (PathBuf, tempfile::TempDir) {
        let dir = private_dir();
        #[cfg(unix)]
        let at = dir.path().join("control.sock");
        #[cfg(windows)]
        let at = PathBuf::from(format!(
            r"\\.\pipe\tenzro-control-test-{}-{}",
            std::process::id(),
            dir.path().file_name().unwrap().to_string_lossy()
        ));
        let bound = server::bind(&at).unwrap();
        tokio::spawn(server::serve(bound, helper));
        (at, dir)
    }

    /// One call the way an app makes it: connect, write a line, read a line.
    async fn ask(at: &std::path::Path, method: &str, params: Value) -> Value {
        #[cfg(unix)]
        let stream = tokio::net::UnixStream::connect(at).await.unwrap();
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(at)
            .unwrap();
        let (read, mut write) = tokio::io::split(stream);
        let request = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
        write
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(read).read_line(&mut line).await.unwrap();
        let answer: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(answer["jsonrpc"], "2.0");
        assert_eq!(answer["id"], 7);
        answer
    }

    #[tokio::test]
    async fn the_socket_answers_the_summary_and_passes_the_nodes_reads_through() {
        let node = node_answering(&[
            (
                "tenzro_getNodeStatus",
                r#"{"state":"Running","roles":["Validator"],"health_status":"Healthy","uptime_secs":90,"block_height":41,"peer_count":3,"data_dir":"/data","disk":{"used_pct":12,"level":"ok","assessment":{"free_bytes":1000}},"operator_did":"did:tenzro:human:op","update":{"binary_version":"0.2.2"},"payee":"0x00000000000000000000000000000000000000aa"}"#,
            ),
            (
                "tenzro_syncing",
                r#"{"state":"following","reason":null,"detail":null,"local_height":41,"network_head":41,"head_heard_ms":200,"behind":0,"behind_before":0,"last_import_ms":900}"#,
            ),
            ("tenzro_getRole", r#"{"roles":["validator"],"roles_str":"validator"}"#),
            (
                "tenzro_getRoleStakes",
                r#"{"address":"0x00000000000000000000000000000000000000aa","stakes":[{"role":"validator","bonded":"5000","required":"5000"}],"totals":[]}"#,
            ),
            ("tenzro_getUpdateNotice", r#"{"latest_version":"0.2.2","severity":null}"#),
            ("eth_getBalance", r#""0x64""#),
        ])
        .await;
        let (at, _dir) = listening(helper(&node, machine()));

        let summary = ask(&at, "control_summary", json!({})).await;
        assert_eq!(
            summary["result"],
            json!({
                "version": "0.2.2",
                "node": {
                    "service": "running",
                    "follow": { "state": "following", "height": 41, "target": 41, "last_block_secs": 0, "reason": null },
                    "peers": 3,
                    "uptime_secs": 90,
                    "health": "healthy",
                    "disk": { "used_pct": 12, "level": "ok", "free_bytes": 1000 },
                },
                "role": { "roles": ["validator"] },
                "stake": {
                    "address": "0x00000000000000000000000000000000000000aa",
                    "bonded": "5000",
                    "required": "5000",
                    "available": "100",
                    "token": "TNZO",
                },
                "identity": {
                    "did": "did:tenzro:human:op",
                    "keys_in": "tpm",
                    "key_holder_label": null,
                    "passkey_bound": true,
                },
                "update": { "current": "0.2.2", "latest": "0.2.2", "severity": null, "auto": null },
                "conditions": 0,
            })
        );

        // The node's answers come back as it gave them: a result, and an
        // error with the node's own code and words.
        let role = ask(&at, "tenzro_getRole", json!([])).await;
        assert_eq!(
            role["result"],
            json!({ "roles": ["validator"], "roles_str": "validator" })
        );
        let unserved = ask(&at, "tenzro_nodeProfile", json!([])).await;
        assert_eq!(
            unserved["error"],
            json!({ "code": -32601, "message": "no such method" })
        );
        assert!(unserved.get("result").is_none());

        // The helper's own table has no such method, and the node is not asked.
        let unknown = ask(&at, "control_noSuchCall", json!({})).await;
        assert_eq!(
            unknown["error"],
            json!({ "code": -32601, "message": "Method not found" })
        );
    }

    #[tokio::test]
    async fn the_socket_answers_while_the_node_is_down() {
        let (at, _dir) = listening(helper(&silent_node(), machine()));

        let summary = ask(&at, "control_summary", json!({})).await;
        assert_eq!(summary["result"]["node"]["service"], "stopped");
        assert_eq!(summary["result"]["node"]["follow"]["state"], "stopped");
        assert_eq!(
            summary["result"]["identity"]["did"],
            "did:tenzro:human:saved"
        );

        let call = ask(&at, "tenzro_getRole", json!([])).await;
        assert_eq!(
            call["error"],
            json!({ "code": -32000, "message": "This machine's node is not answering." })
        );
    }

    #[tokio::test]
    async fn one_connection_carries_several_calls_and_survives_a_bad_line() {
        let helper = helper(&silent_node(), machine());
        assert_eq!(
            serde_json::from_str::<Value>(&helper.answer(b"not json").await.unwrap()).unwrap(),
            json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "the request is not JSON" } })
        );
        assert_eq!(
            serde_json::from_str::<Value>(&helper.answer(br#"{"id":"a"}"#).await.unwrap()).unwrap(),
            json!({ "jsonrpc": "2.0", "id": "a", "error": { "code": -32600, "message": "the request names no method" } })
        );

        // A message without an id is not answered.
        assert_eq!(
            helper.answer(br#"{"method":"control_summary"}"#).await,
            None
        );

        let (at, _dir) = listening(helper);
        #[cfg(unix)]
        let stream = tokio::net::UnixStream::connect(&at).await.unwrap();
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&at)
            .unwrap();
        let (read, mut write) = tokio::io::split(stream);
        let mut lines = BufReader::new(read).lines();
        write
            .write_all(
                b"not json\n\n\xff\xfe not text\n{\"method\":\"control_summary\"}\n{\"id\":2,\"method\":\"control_summary\"}\n",
            )
            .await
            .unwrap();
        for _ in ["not json", "not text"] {
            let bad: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(bad["error"]["code"], -32700);
            assert_eq!(bad["id"], Value::Null);
        }
        // The message without an id drew no line: the next one answers id 2.
        let second: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(second["id"], 2);
        assert_eq!(second["result"]["node"]["service"], "stopped");
    }

    #[cfg(unix)]
    type Opened = tokio::net::UnixStream;
    #[cfg(windows)]
    type Opened = tokio::net::windows::named_pipe::NamedPipeClient;

    /// One connection to the helper: its answers line by line, and where to write.
    async fn open(
        at: &std::path::Path,
    ) -> (
        tokio::io::Lines<BufReader<tokio::io::ReadHalf<Opened>>>,
        tokio::io::WriteHalf<Opened>,
    ) {
        #[cfg(unix)]
        let stream = tokio::net::UnixStream::connect(at).await.unwrap();
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(at)
            .unwrap();
        let (read, write) = tokio::io::split(stream);
        (BufReader::new(read).lines(), write)
    }

    #[tokio::test]
    async fn a_line_longer_than_the_helper_reads_is_answered_and_the_connection_closed() {
        let (at, _dir) = listening(helper(&silent_node(), machine()));
        let (mut answers, mut write) = open(&at).await;
        let longest = usize::try_from(server::LONGEST_LINE).unwrap();

        // The longest line the helper reads is answered like any other.
        let mut fits = br#"{"id":1,"method":"control_summary"}"#.to_vec();
        fits.resize(longest, b' ');
        fits.push(b'\n');
        write.write_all(&fits).await.unwrap();
        let answered: Value =
            serde_json::from_str(&answers.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(answered["id"], 1);
        assert_eq!(answered["result"]["node"]["service"], "stopped");

        // One byte more, and no end of line in sight.
        write.write_all(&vec![b' '; longest + 1]).await.unwrap();
        let refused: Value =
            serde_json::from_str(&answers.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(refused["id"], Value::Null);
        assert_eq!(
            refused["error"],
            json!({ "code": -32600, "message": "The request line is longer than the helper reads." })
        );
        assert!(matches!(answers.next_line().await, Ok(None) | Err(_)));
    }

    #[tokio::test]
    async fn the_helper_answers_so_many_connections_at_once_and_no_more() {
        let (at, _dir) = listening(helper(&silent_node(), machine()));
        // A call the helper answers without the node: where a refused
        // connection takes seconds to fail, asking the node would keep the
        // first seats silent past the idle close and free them.
        let call = b"{\"id\":1,\"method\":\"control_seat\"}\n";
        let mut seated = Vec::new();
        for _ in 0..server::MOST_CONNECTIONS {
            let (mut answers, mut write) = open(&at).await;
            write.write_all(call).await.unwrap();
            let answered: Value =
                serde_json::from_str(&answers.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(answered["id"], 1);
            assert_eq!(answered["error"]["code"], METHOD_NOT_FOUND);
            seated.push((answers, write));
        }

        let (mut answers, _write) = open(&at).await;
        let full: Value =
            serde_json::from_str(&answers.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(full["id"], Value::Null);
        assert_eq!(
            full["error"],
            json!({
                "code": -32000,
                "message": "The helper has as many connections open as it answers at once.",
            })
        );
        assert!(matches!(answers.next_line().await, Ok(None) | Err(_)));

        // Those already seated are still answered, and a seat one of them
        // leaves goes to the next to come.
        let (answers, write) = &mut seated[0];
        write.write_all(call).await.unwrap();
        assert!(answers.next_line().await.unwrap().is_some());
        seated.pop();
        let mut answered = None;
        for _ in 0..100 {
            let (mut answers, mut write) = open(&at).await;
            let _ = write.write_all(call).await;
            match answers.next_line().await {
                Ok(Some(line)) if !line.contains("as many connections") => {
                    answered = Some(line);
                    break;
                }
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let answered: Value = serde_json::from_str(&answered.expect("a seat came free")).unwrap();
        assert_eq!(answered["id"], 1);
        assert_eq!(answered["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn every_read_passed_on_is_open_on_the_node() {
        // The node's gate table: a read later moved to the owner's or the
        // administrators' methods must not be called with the user's session.
        let gates = include_str!("../../../../tenzro-node/src/rpc_gates.rs");
        let open = gates
            .split_once("pub const OPEN_METHODS: &[&str] = &[")
            .and_then(|(_, rest)| rest.split_once("\n];"))
            .expect("the node lists its open methods")
            .0;
        let open: Vec<&str> = open
            .lines()
            .filter_map(|line| line.trim().strip_prefix('"')?.strip_suffix("\","))
            .collect();
        for read in NODE_READS {
            assert!(open.contains(read), "{read} is not open on the node");
        }
    }

    #[tokio::test]
    async fn a_node_method_that_is_not_a_listed_read_never_reaches_the_node() {
        assert!(
            NODE_READS.windows(2).all(|pair| pair[0] < pair[1]),
            "the list is searched as a sorted one"
        );
        // A node that would answer every one of these, were it asked.
        let node = node_answering(&[
            ("eth_getBalance", r#""reached""#),
            ("eth_sendRawTransaction", r#""reached""#),
            ("tenzro_gracefulExit", r#""reached""#),
            ("tenzro_installUpdate", r#""reached""#),
            ("tenzro_pairDevice", r#""reached""#),
            ("tenzro_restartNode", r#""reached""#),
            ("tenzro_revokeBoundDevice", r#""reached""#),
            ("tenzro_submitApproval", r#""reached""#),
            ("tenzro_unpairDevice", r#""reached""#),
        ])
        .await;
        let (at, _dir) = listening(helper(&node, machine()));
        for method in [
            "eth_getBalance",
            "eth_sendRawTransaction",
            "tenzro_gracefulExit",
            "tenzro_installUpdate",
            "tenzro_pairDevice",
            "tenzro_restartNode",
            "tenzro_revokeBoundDevice",
            "tenzro_submitApproval",
            "tenzro_unpairDevice",
            "",
        ] {
            let refused = ask(&at, method, json!([])).await;
            assert_eq!(
                refused["error"],
                json!({
                    "code": -32000,
                    "message": "The helper passes only reads to this machine's node, and this call is not one of them.",
                }),
                "{method}"
            );
            assert!(refused.get("result").is_none(), "{method}");
        }
    }

    #[tokio::test]
    async fn a_node_that_takes_a_call_and_never_answers_does_not_hold_the_caller() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((call, _)) = listener.accept().await {
                held.push(call);
            }
        });
        let mut local = machine();
        local.node_process = true;
        let (at, _dir) = listening(helper_waiting(&node, local, Duration::from_millis(300)));

        let answers = async {
            let call = ask(&at, "tenzro_getRole", json!([])).await;
            assert_eq!(
                call["error"],
                json!({ "code": -32000, "message": "This machine's node is not answering." })
            );
            let summary = ask(&at, "control_summary", json!({})).await;
            assert!(
                summary["result"]["node"]["service"].is_string(),
                "{summary}"
            );
        };
        tokio::time::timeout(Duration::from_secs(20), answers)
            .await
            .expect("the helper answers although the node does not");
    }

    #[tokio::test]
    async fn a_node_elsewhere_is_refused_unless_the_operator_says_so() {
        for here in [
            crate::endpoint::LOCAL_RPC,
            "http://127.0.0.1:8545",
            "http://127.9.9.9:1",
            "http://localhost:8545/",
            "http://[::1]:8545",
        ] {
            assert!(on_this_machine(here), "{here}");
        }
        for elsewhere in [
            "http://10.0.0.5:8545",
            "http://0.0.0.0:8545",
            "http://[2001:db8::1]:8545",
            "https://node.example:8545",
            "http://localhost.example:8545",
            "http://127.0.0.1.example:8545",
            "127.0.0.1:8545",
            "",
        ] {
            assert!(!on_this_machine(elsewhere), "{elsewhere}");
        }

        let dir = tempfile::tempdir().unwrap();
        let command = ControlCmd {
            node: "http://10.0.0.5:8545".into(),
            remote_node: false,
            web: None,
            web_port: 8765,
            socket: Some(dir.path().join("control.sock")),
        };
        let refused = command.execute().await.unwrap_err().to_string();
        assert!(refused.contains("is not on this machine"), "{refused}");
        assert!(refused.contains("--remote-node"), "{refused}");
        assert!(!dir.path().join("control.sock").exists());
    }

    #[tokio::test]
    async fn the_socket_walks_setup_and_a_new_helper_picks_it_up() {
        let node = node_answering(&[("web3_clientVersion", r#""tenzro/0.2.2""#)]).await;
        let kept = tempfile::tempdir().unwrap();
        let file = kept.path().join("setup-progress.json");
        let serving = || {
            listening(helper_with(
                &node,
                machine(),
                setup::tests::ready(file.clone()),
            ))
        };
        let refused = |answer: &Value| {
            (
                answer["error"]["code"].as_i64().unwrap(),
                answer["error"]["message"].as_str().unwrap().to_string(),
            )
        };
        let (at, _dir) = serving();

        let plan = ask(&at, "control_setupPlan", json!({})).await;
        assert_eq!(plan["result"]["path"], "validate");
        assert_eq!(plan["result"]["steps"][0]["id"], "role");
        assert_eq!(plan["result"]["steps"][0]["kind"], "choose_role");
        assert_eq!(plan["result"]["steps"][0]["state"], "pending");
        assert_eq!(plan["result"]["roles"][1]["id"], "operate");
        let early = ask(&at, "control_setupRun", json!({ "step_id": "hardware" })).await;
        assert_eq!(
            refused(&early),
            (
                -32000,
                "Finish \"What do you want to do?\" first".to_string()
            )
        );

        let chosen = ask(
            &at,
            "control_setupRun",
            json!({ "step_id": "role", "choice": "operate" }),
        )
        .await;
        assert_eq!(chosen["result"]["state"], "done");
        let plan = ask(&at, "control_setupPlan", json!({})).await;
        assert_eq!(plan["result"]["path"], "operate");
        assert_eq!(plan["result"]["blocked"], Value::Null);
        let steps = plan["result"]["steps"].as_array().unwrap();
        assert_eq!(steps[0]["state"], "done");
        assert_eq!(steps[1]["id"], "hardware");
        assert_eq!(steps[1]["state"], "pending");

        let last = steps.last().unwrap()["id"].as_str().unwrap();
        let ahead = ask(&at, "control_setupRun", json!({ "step_id": last })).await;
        assert_eq!(
            refused(&ahead),
            (
                -32000,
                format!("Finish \"{}\" first", steps[1]["title"].as_str().unwrap())
            )
        );
        let skipped = ask(&at, "control_setupSkip", json!({ "step_id": "hardware" })).await;
        assert_eq!(
            refused(&skipped),
            (-32000, "This step cannot be skipped".to_string())
        );

        let done = ask(&at, "control_setupRun", json!({ "step_id": "hardware" })).await;
        assert_eq!(done["result"]["id"], "hardware");
        assert_eq!(done["result"]["state"], "done");
        let again = ask(&at, "control_setupRun", json!({ "step_id": "hardware" })).await;
        assert_eq!(again["result"], done["result"]);

        // The node's reads still pass through the same socket.
        let version = ask(&at, "web3_clientVersion", json!([])).await;
        assert_eq!(version["result"], "tenzro/0.2.2");
        let unknown = ask(&at, "control_setupUndo", json!({})).await;
        assert_eq!(refused(&unknown), (-32601, "Method not found".to_string()));

        let (at, _dir) = serving();
        let plan = ask(&at, "control_setupPlan", json!({})).await;
        assert_eq!(plan["result"]["path"], "operate");
        let steps = plan["result"]["steps"].as_array().unwrap();
        assert_eq!(steps[0]["state"], "done");
        assert_eq!(steps[1]["state"], "done");
        assert_eq!(steps[2]["state"], "pending");
    }

    #[tokio::test]
    async fn the_socket_runs_a_passkey_ceremony_to_its_end() {
        let node = node_answering(ceremony::tests::ENROLLED).await;
        let kept = tempfile::tempdir().unwrap();
        let (at, _dir) = listening(assembled(
            &node,
            machine(),
            NODE_ANSWER_WAIT,
            setup::tests::ready(PathBuf::new()),
            ceremony::tests::kept_in(&node, kept.path(), Duration::from_secs(60)),
        ));

        let started = ask(&at, "control_ceremony", json!({ "purpose": "enroll" })).await;
        let waiting = &started["result"];
        assert_eq!(waiting["state"], "waiting");
        assert_eq!(waiting["reason"], Value::Null);
        assert_eq!(waiting["qr"], waiting["url"]);
        let url = waiting["url"].as_str().unwrap();
        assert!(url.starts_with("https://"));
        let rows = waiting["qr_rows"].as_array().unwrap();
        assert!(rows.len() >= 21);
        assert!(rows.iter().all(|row| {
            let row = row.as_str().unwrap();
            row.len() == rows.len() && row.chars().all(|c| c == '0' || c == '1')
        }));
        let id = waiting["id"].clone();
        let asked = ask(&at, "control_ceremonyStatus", json!({ "id": id })).await;
        assert_eq!(asked["result"], *waiting);

        ceremony::tests::approve(url).await;
        let mut end = Value::Null;
        for _ in 0..500 {
            end = ask(&at, "control_ceremonyStatus", json!({ "id": id })).await["result"].clone();
            if end["state"] != "waiting" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(end["state"], "done");
        assert_eq!(end["id"], id);
        assert_eq!(end["url"], waiting["url"]);
        let cfg = crate::config::load_config_in(kept.path());
        assert_eq!(cfg.did.as_deref(), Some("did:tenzro:human:7"));
        assert_eq!(cfg.wallet_address.as_deref(), Some("0x07"));

        let unknown = ask(&at, "control_ceremonyStatus", json!({ "id": "c0" })).await;
        assert_eq!(
            unknown["error"],
            json!({ "code": -32602, "message": "No such ceremony" })
        );
        let bind = ask(&at, "control_ceremony", json!({ "purpose": "bind" })).await;
        assert_eq!(bind["error"]["code"], -32000);
    }
}
