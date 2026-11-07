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

use anyhow::{Result, anyhow};

use super::journey::Prog;

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
    let path = resolve(prog).ok_or_else(|| anyhow!("{} was not found on this machine", prog.name()))?;
    let mut cmd = base_command(&path, args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| anyhow!("could not start {}: {e}", prog.name()))?;
    let (tx, rx) = channel();
    pump(child.stdout.take(), tx.clone());
    pump(child.stderr.take(), tx.clone());
    let child = Arc::new(Mutex::new(child));
    let waiter = child.clone();
    std::thread::spawn(move || {
        // Poll rather than hold the lock in `wait`, so `kill` can take it.
        loop {
            let status = waiter.lock().ok().and_then(|mut c| c.try_wait().ok().flatten());
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

fn pump<R: std::io::Read + Send + 'static>(r: Option<R>, tx: Sender<Msg>) {
    if let Some(r) = r {
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines().map_while(|l| l.ok()) {
                if tx.send(Msg::Line(line)).is_err() {
                    break;
                }
            }
        });
    }
}

/// Start `prog args` and leave it running, its output in `log`. Returns the
/// process id.
pub fn spawn_detached(prog: &Prog, args: &[String], log: &Path) -> Result<u32> {
    let path = resolve(prog).ok_or_else(|| anyhow!("{} was not found on this machine", prog.name()))?;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let out = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
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
    let child = cmd.spawn().map_err(|e| anyhow!("could not start {}: {e}", prog.name()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_command_streams_its_lines_and_its_exit_code() {
        let r = spawn(&Prog::Other("sh"), &["-c".into(), "echo one; echo two 1>&2; exit 3".into()]).unwrap();
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
    fn the_environment_is_colourless_and_not_echoed() {
        let r = spawn(&Prog::Other("sh"), &["-c".into(), "echo $NO_COLOR $TERM".into()]).unwrap();
        let m = r.rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(matches!(m, Msg::Line(l) if l == "1 dumb"));
    }

    #[test]
    fn a_missing_program_is_a_plain_error() {
        let e = spawn(&Prog::Other("definitely-not-a-program-xyz"), &[]).err().unwrap();
        assert!(e.to_string().contains("was not found"));
    }
}
