//! Running a step's command and streaming what it prints.
//!
//! The command is run as a child process of this program (the same `tenzro`,
//! or `tenzro-node`), with no terminal of its own and colour off, so its
//! output arrives as plain lines for the screen. Nothing it prints is
//! written anywhere except the one file a step names (a list of public key
//! handles), and the environment is never shown.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};

use super::journey::{Action, Opts, Prog, Step};

/// What a running command reports.
#[derive(Debug)]
pub enum Msg {
    Line(String),
    /// The command ended; `None` when it was stopped by a signal.
    Exit(Option<i32>),
}

pub struct Running {
    pub rx: Receiver<Msg>,
    child: Arc<Mutex<Child>>,
}

impl Running {
    /// Stop the command.
    pub fn kill(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
        }
    }
}

/// Where a program is: this executable, `tenzro-node` beside it or on PATH,
/// or any other program on PATH.
pub fn resolve(prog: &Prog) -> Option<PathBuf> {
    match prog {
        Prog::Cli => std::env::current_exe().ok(),
        Prog::Node => crate::commands::setup::locate_node_binary(),
        Prog::Other(n) => crate::commands::setup::which_on_path(n),
    }
}

fn base_command(path: &Path, args: &[String]) -> Command {
    let mut c = Command::new(path);
    c.args(args)
        .stdin(Stdio::null())
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .env("TENZRO_NO_BANNER", "1");
    c
}

/// Run `prog args` and stream its output.
pub fn spawn(prog: &Prog, args: &[String]) -> Result<Running> {
    let path =
        resolve(prog).ok_or_else(|| anyhow!("{} was not found on this machine", prog.name()))?;
    let mut cmd = base_command(&path, args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("could not start {}: {e}", prog.name()))?;
    let (tx, rx) = channel();
    pump(child.stdout.take(), tx.clone());
    pump(child.stderr.take(), tx.clone());
    let child = Arc::new(Mutex::new(child));
    let waiter = child.clone();
    std::thread::spawn(move || {
        // Poll rather than hold the lock in `wait`, so `kill` can take it.
        loop {
            let status = waiter
                .lock()
                .ok()
                .and_then(|mut c| c.try_wait().ok().flatten());
            if let Some(st) = status {
                // Give the readers a moment to flush the last lines.
                std::thread::sleep(std::time::Duration::from_millis(150));
                let _ = tx.send(Msg::Exit(st.code()));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    Ok(Running { rx, child })
}

/// The most of one output line that is kept; the rest of a longer line is
/// read and dropped.
const LINE_BYTES: usize = 4096;

/// Sends what a command prints, line by line. It reads bytes, so output that
/// is not UTF-8 is shown with replacement characters instead of ending the
/// stream, and it reads to the end whatever it keeps, so the command never
/// blocks on a full pipe.
fn pump<R: std::io::Read + Send + 'static>(r: Option<R>, tx: Sender<Msg>) {
    if let Some(r) = r {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(r);
            let mut line = Vec::new();
            loop {
                let buf = match reader.fill_buf() {
                    Ok([]) => break,
                    Ok(buf) => buf,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                let (used, ended) = match buf.iter().position(|b| *b == b'\n') {
                    Some(at) => (at + 1, true),
                    None => (buf.len(), false),
                };
                let text = if ended { used - 1 } else { used };
                let room = LINE_BYTES.saturating_sub(line.len());
                line.extend_from_slice(&buf[..text.min(room)]);
                reader.consume(used);
                if ended && !send_line(&tx, &mut line) {
                    return;
                }
            }
            if !line.is_empty() {
                send_line(&tx, &mut line);
            }
        });
    }
}

/// Sends one line and empties it; `false` once nobody is listening.
fn send_line(tx: &Sender<Msg>, line: &mut Vec<u8>) -> bool {
    let text = String::from_utf8_lossy(line);
    let text = text.strip_suffix('\r').unwrap_or(&text).to_string();
    line.clear();
    tx.send(Msg::Line(text)).is_ok()
}

/// Start `prog args` and leave it running, its output in `log`. Returns the
/// process id.
pub fn spawn_detached(prog: &Prog, args: &[String], log: &Path) -> Result<u32> {
    let path =
        resolve(prog).ok_or_else(|| anyhow!("{} was not found on this machine", prog.name()))?;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    let err = out.try_clone()?;
    let mut cmd = base_command(&path, args);
    cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    let child = cmd
        .spawn()
        .map_err(|e| anyhow!("could not start {}: {e}", prog.name()))?;
    Ok(child.id())
}

/// Keep `text` in `dir/name` (used for the public key-handle list only).
pub fn save_output(dir: &Path, name: &str, text: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p)?;
    f.write_all(text.as_bytes())?;
    Ok(p)
}

/// How many times a waiting step asks the node before it gives up.
const WAIT_CHECKS: u32 = 30;

/// How long a waiting step rests between two asks.
const WAIT_PAUSE: Duration = Duration::from_secs(2);

/// Why a waiting step failed.
pub const NODE_SILENT: &str = "the node did not answer within a minute";

/// What starting a step led to.
pub enum Begun {
    /// It is done already; the line says what happened.
    Done(Option<String>),
    /// It could not start, or what it does at once failed.
    Failed(String),
    /// Its command runs; [`finish`] closes the step when the command ends.
    Running(Running),
    /// It waits for the node at this address; [`wait_for_node`] does the
    /// waiting.
    Waiting(String),
}

/// Start `step`. A command left running writes its output to `node.log` in
/// the data directory `o` names.
pub fn begin(step: &Step, o: &Opts) -> Begun {
    match &step.action {
        Action::None => Begun::Done(None),
        Action::Exec {
            prog,
            args,
            detached: true,
            ..
        } => {
            let log = o.data_dir.join("node.log");
            match spawn_detached(prog, args, &log) {
                Ok(pid) => Begun::Done(Some(format!(
                    "Started (process {pid}). Its log: {}",
                    log.display()
                ))),
                Err(e) => Begun::Failed(e.to_string()),
            }
        }
        Action::Exec { prog, args, .. } => match spawn(prog, args) {
            Ok(r) => Begun::Running(r),
            Err(e) => Begun::Failed(e.to_string()),
        },
        Action::WaitRpc { url } => Begun::Waiting(url.clone()),
        Action::SaveLocalConfig => {
            let mut cfg = crate::config::load_config();
            cfg.endpoint = Some(crate::endpoint::LOCAL_RPC.to_string());
            match crate::config::save_config(&cfg) {
                Ok(()) => Begun::Done(Some(format!(
                    "Saved to {}",
                    crate::config::config_path().display()
                ))),
                Err(e) => Begun::Failed(e.to_string()),
            }
        }
    }
}

/// Close a step whose command ended with `code`, having printed `captured`.
/// A command that succeeded leaves what the step keeps: the output a step
/// saves, and the key holder a successful check found. `Ok` carries a line
/// to show; `Err` says why the step failed.
pub fn finish(
    step: &Step,
    code: Option<i32>,
    captured: &[String],
    o: &Opts,
) -> std::result::Result<Option<String>, String> {
    match code {
        Some(0) => {}
        Some(c) => return Err(format!("it stopped with exit code {c}")),
        None => return Err("it was stopped".into()),
    }
    let mut said = None;
    if let Action::Exec {
        save_as: Some(name),
        ..
    } = &step.action
    {
        said = Some(match save_output(&o.data_dir, name, &captured.join("\n")) {
            Ok(p) => format!("Kept the list in {}", p.display()),
            Err(e) => format!("Could not keep the list: {e}"),
        });
    }
    if step.id == "holder-check" {
        let mut cfg = crate::config::load_config();
        cfg.key_holder_socket = Some(o.holder_socket.clone());
        cfg.key_holder_label = Some(o.holder_label.clone());
        let _ = crate::config::save_config(&cfg);
    }
    Ok(said)
}

/// What a waiting step says while it asks for the `attempt`th time.
pub fn wait_message(attempt: u32) -> String {
    format!("check {attempt} of {WAIT_CHECKS}")
}

/// Ask the node at `url` until it answers, telling `heard` the number of each
/// ask. False when it stayed silent through every ask.
pub async fn wait_for_node(url: &str, mut heard: impl FnMut(u32)) -> bool {
    for attempt in 1..=WAIT_CHECKS {
        heard(attempt);
        if super::detect::check_network(url).await.is_reachable() {
            return true;
        }
        tokio::time::sleep(WAIT_PAUSE).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_command_streams_its_lines_and_its_exit_code() {
        let r = spawn(
            &Prog::Other("sh"),
            &["-c".into(), "echo one; echo two 1>&2; exit 3".into()],
        )
        .unwrap();
        let mut lines = Vec::new();
        let mut code = None;
        while let Ok(m) = r.rx.recv_timeout(std::time::Duration::from_secs(5)) {
            match m {
                Msg::Line(l) => lines.push(l),
                Msg::Exit(c) => {
                    code = c;
                    break;
                }
            }
        }
        lines.sort();
        assert_eq!(lines, ["one", "two"]);
        assert_eq!(code, Some(3));
    }

    #[cfg(unix)]
    #[test]
    fn output_that_is_not_text_or_too_long_neither_stops_nor_blocks_the_stream() {
        let script = "printf 'a\\377b\\r\\nnext\\n'; head -c 200000 /dev/zero | tr '\\0' x; \
                      echo; echo end; printf tail";
        let r = spawn(&Prog::Other("sh"), &["-c".into(), script.into()]).unwrap();
        let mut lines = Vec::new();
        let mut wait = std::time::Duration::from_secs(5);
        while let Ok(m) = r.rx.recv_timeout(wait) {
            match m {
                Msg::Line(l) => lines.push(l),
                // Lines may still be on their way when the exit arrives.
                Msg::Exit(_) => wait = std::time::Duration::from_millis(500),
            }
        }
        assert_eq!(
            lines.len(),
            5,
            "{:?}",
            lines.iter().map(|l| l.len()).collect::<Vec<_>>()
        );
        assert_eq!(lines[0], "a\u{fffd}b");
        assert_eq!(lines[1], "next");
        assert_eq!(lines[2], "x".repeat(LINE_BYTES));
        assert_eq!(lines[3], "end");
        assert_eq!(lines[4], "tail");
    }

    #[cfg(unix)]
    #[test]
    fn the_environment_is_colourless_and_not_echoed() {
        let r = spawn(
            &Prog::Other("sh"),
            &["-c".into(), "echo $NO_COLOR $TERM".into()],
        )
        .unwrap();
        let m =
            r.rx.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        assert!(matches!(m, Msg::Line(l) if l == "1 dumb"));
    }

    #[test]
    fn a_missing_program_is_a_plain_error() {
        let e = spawn(&Prog::Other("definitely-not-a-program-xyz"), &[])
            .err()
            .unwrap();
        assert!(e.to_string().contains("was not found"));
    }
}
