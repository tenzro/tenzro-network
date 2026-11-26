//! The web console: the page's files, the helper's own calls and the node's
//! calls behind one address that only this machine can reach.
//!
//! The command prints a link that carries a ticket. The page that opens the
//! link hands the ticket in once and is signed in; from then on it sends the
//! ticket with every call, and it stays signed in while it keeps calling.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use super::server::{ACCEPT_PAUSE, MOST_CONNECTIONS, stopped};
use super::{Helper, error, response};
use crate::onboarding::ceremony::{CONN_TIMEOUT, HttpRequest, read_request, try_open_browser};

/// How long the link waits for a page to open it, and how long a signed-in
/// page may stay silent.
const QUIET_ALLOWED: Duration = Duration::from_secs(15 * 60);

/// The header a signed-in page sends its ticket in.
const TICKET_HEADER: &str = "x-tenzro-access-ticket";

/// The call does not come from the signed-in page.
const NOT_SIGNED_IN: i64 = -32004;

const TEXT: &str = "text/plain; charset=utf-8";
const JSON: &str = "application/json";

/// Who may call: nobody until one page hands the ticket in, then whoever
/// sends that ticket, until it has been silent too long.
struct Door {
    ticket: String,
    /// Whether a page has handed the ticket in.
    opened: bool,
    /// When the ticket was made, handed in, or last sent with a call.
    heard: Instant,
}

impl Door {
    fn new(now: Instant) -> Self {
        Self {
            ticket: hex::encode(rand::random::<[u8; 32]>()),
            opened: false,
            heard: now,
        }
    }

    /// Whether `offered` is the ticket and it still stands. The two are
    /// compared by digest, so how long the comparison takes says nothing
    /// about the ticket.
    fn holds(&self, offered: &str, now: Instant) -> bool {
        now.duration_since(self.heard) < QUIET_ALLOWED
            && Sha256::digest(offered.as_bytes()) == Sha256::digest(self.ticket.as_bytes())
    }

    /// Signs in the page that hands the ticket in. The ticket does this once.
    fn open(&mut self, offered: &str, now: Instant) -> bool {
        if self.opened || !self.holds(offered, now) {
            return false;
        }
        self.opened = true;
        self.heard = now;
        true
    }

    /// Whether a call that carries `offered` comes from the signed-in page.
    fn admits(&mut self, offered: Option<&str>, now: Instant) -> bool {
        let known = self.opened && offered.is_some_and(|ticket| self.holds(ticket, now));
        if known {
            self.heard = now;
        }
        known
    }
}

/// The console: the directory its page is served from, the helper that
/// answers its calls, and who is signed in.
struct Console {
    files: PathBuf,
    helper: Arc<Helper>,
    door: Mutex<Door>,
}

impl Console {
    fn over(files: &Path, helper: Arc<Helper>) -> Result<Arc<Self>> {
        let files = files
            .canonicalize()
            .with_context(|| format!("{} cannot be read", files.display()))?;
        if !files.is_dir() {
            return Err(anyhow!("{} is not a directory", files.display()));
        }
        Ok(Arc::new(Self {
            files,
            helper,
            door: Mutex::new(Door::new(Instant::now())),
        }))
    }

    fn door(&self) -> MutexGuard<'_, Door> {
        self.door.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The link that signs one page in.
    fn link(&self, port: u16) -> String {
        format!("http://127.0.0.1:{port}/#t={}", self.door().ticket)
    }

    /// Answers one request.
    async fn answer(&self, request: &HttpRequest) -> Vec<u8> {
        if !named_locally(request.header("host")) {
            return reply(403, TEXT, b"this address answers to its local name only");
        }
        let path = request.path.split('?').next().unwrap_or_default();
        match (request.method.as_str(), path) {
            ("POST", "/control") => self.call(true, request).await,
            ("POST", "/rpc") => self.call(false, request).await,
            ("POST", _) => not_found(),
            ("GET", _) => match file_under(&self.files, path) {
                Some(file) => match tokio::fs::read(&file).await {
                    Ok(body) => reply(200, kind_of(&file), &body),
                    Err(_) => not_found(),
                },
                None => not_found(),
            },
            _ => reply(405, TEXT, b"use GET or POST"),
        }
    }

    /// One call from the page. `/control` carries the helper's own methods
    /// and `/rpc` the node's; a method sent to the other path is not found.
    /// Only the call that hands the ticket in is answered before sign-in.
    async fn call(&self, own: bool, request: &HttpRequest) -> Vec<u8> {
        let body = String::from_utf8_lossy(&request.body);
        let asked: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let method = asked.get("method").and_then(Value::as_str);
        if method.is_some_and(|method| method.starts_with("control_") != own) {
            return not_found();
        }
        let now = Instant::now();
        let signed_in = if method == Some("control_session") {
            let offered = asked
                .get("params")
                .and_then(|params| params.get("ticket"))
                .and_then(Value::as_str);
            offered
                .is_some_and(|ticket| self.door().open(ticket, now))
                .then(|| json!({ "operator": true, "expires_in_secs": QUIET_ALLOWED.as_secs() }))
        } else if self.door().admits(request.header(TICKET_HEADER), now) {
            return match self.helper.answer(&request.body).await {
                Some(answer) => reply(200, JSON, answer.as_bytes()),
                None => reply(204, JSON, b""),
            };
        } else {
            None
        };
        let outcome = signed_in.ok_or_else(|| {
            error(
                NOT_SIGNED_IN,
                "This page is not signed in. Run `tenzro control --web` again for a new link.",
            )
        });
        let id = asked.get("id").cloned().unwrap_or(Value::Null);
        reply(200, JSON, response(id, outcome).as_bytes())
    }
}

/// Whether the request was addressed to this machine by a local name. A page
/// on another site that points a name of its own at this machine fails here.
fn named_locally(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    matches!(name, "127.0.0.1" | "localhost" | "::1")
}

/// The file under `root` that `path` names, when it names one inside it.
/// Names that begin with a dot are not served, which also keeps `..` out.
fn file_under(root: &Path, path: &str) -> Option<PathBuf> {
    let named = unescaped(path.strip_prefix('/')?)?;
    let named = if named.is_empty() {
        "index.html"
    } else {
        named.as_str()
    };
    let mut file = root.to_path_buf();
    for part in named.split('/') {
        if part.is_empty() || part.starts_with('.') || part.contains(['\\', ':', '\0']) {
            return None;
        }
        file.push(part);
    }
    let file = file.canonicalize().ok()?;
    (file.starts_with(root) && file.is_file()).then_some(file)
}

/// `text` with its percent escapes read; nothing when an escape is broken or
/// what comes out is not text.
fn unescaped(text: &str) -> Option<String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let pair = [bytes.next()?, bytes.next()?];
            out.extend(hex::decode(pair).ok()?);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
}

/// The content type a file is served with.
fn kind_of(file: &Path) -> &'static str {
    match file.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("webmanifest") => "application/manifest+json",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn not_found() -> Vec<u8> {
    reply(404, TEXT, b"not found")
}

/// One whole HTTP answer. Nothing it carries is kept by the browser or read
/// as another type than the one named.
fn reply(status: u16, kind: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Bad Request",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Takes `port` on this machine's own address, which no other machine can
/// reach.
async fn listen(port: u16) -> Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| {
            format!("Port {port} on this machine cannot be taken; name another with --web-port")
        })
}

/// Answers every request that reaches `listener`, one per connection, and as
/// many connections at once as the socket would; one more is closed unanswered.
async fn serve(listener: TcpListener, console: Arc<Console>) {
    let seats = Arc::new(Semaphore::new(MOST_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if let Ok(seat) = seats.clone().try_acquire_owned() {
                    let console = console.clone();
                    tokio::spawn(async move {
                        converse(stream, console).await;
                        drop(seat);
                    });
                }
            }
            Err(_) => tokio::time::sleep(ACCEPT_PAUSE).await,
        }
    }
}

async fn converse(mut stream: TcpStream, console: Arc<Console>) {
    let answer = match tokio::time::timeout(CONN_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => console.answer(&request).await,
        Ok(Err((status, why))) => reply(status, TEXT, why.as_bytes()),
        Err(_) => return,
    };
    let _ = stream.write_all(&answer).await;
    let _ = stream.shutdown().await;
}

/// Serves the console in `files` on `port` until the process is told to stop.
/// The web console a release install keeps beside the running `tenzro`.
pub(crate) fn installed_console() -> Result<PathBuf> {
    console_beside(&std::env::current_exe().context("find the running tenzro")?)
}

/// The console's files for the `tenzro` at `exe`: `share/console` beside
/// the `bin/` it is in, once links are followed, as the release archives and
/// the packages made from them lay it out.
fn console_beside(exe: &Path) -> Result<PathBuf> {
    let exe = exe
        .canonicalize()
        .with_context(|| format!("{} cannot be read", exe.display()))?;
    let dir = exe
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("share").join("console"))
        .ok_or_else(|| anyhow!("{} is not in an install directory", exe.display()))?;
    if !dir.join("index.html").is_file() {
        return Err(anyhow!(
            "The web console's files are not at {}, where a release install keeps them. Pass --web <DIR> to serve them from a folder.",
            dir.display()
        ));
    }
    Ok(dir)
}

pub(crate) async fn run(files: &Path, port: u16, helper: Arc<Helper>) -> Result<()> {
    let console = Console::over(files, helper)?;
    let listener = listen(port).await?;
    let link = console.link(listener.local_addr()?.port());
    crate::output::print_info(&format!(
        "Serving the console in {} to this machine only",
        console.files.display()
    ));
    crate::output::print_info(&format!(
        "This link signs one page in, once, within {} minutes: {link}",
        QUIET_ALLOWED.as_secs() / 60
    ));
    if try_open_browser(&link) {
        crate::output::print_info("Opening it in your browser.");
    }
    tokio::select! {
        () = serve(listener, console) => {}
        () = stopped() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, machine};
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;
    use tokio::io::AsyncReadExt;

    #[test]
    fn the_ticket_signs_one_page_in_once() {
        let start = Instant::now();
        let mut door = Door::new(start);
        let ticket = door.ticket.clone();
        assert_eq!(ticket.len(), 64);
        assert!(!door.admits(Some(&ticket), start), "not before sign-in");
        assert!(!door.open("not-the-ticket", start));
        assert!(door.open(&ticket, start));
        assert!(!door.open(&ticket, start), "a ticket opens the door once");
        assert!(door.admits(Some(&ticket), start));
        assert!(!door.admits(Some("not-the-ticket"), start));
        assert!(!door.admits(None, start));
    }

    #[test]
    fn a_link_nobody_opened_in_time_signs_nobody_in() {
        let start = Instant::now();
        let mut door = Door::new(start);
        let ticket = door.ticket.clone();
        assert!(!door.open(&ticket, start + QUIET_ALLOWED));
        assert!(door.open(&ticket, start + QUIET_ALLOWED - Duration::from_secs(1)));
    }

    #[test]
    fn a_page_stays_signed_in_while_it_keeps_calling() {
        let start = Instant::now();
        let mut door = Door::new(start);
        let ticket = door.ticket.clone();
        assert!(door.open(&ticket, start));
        let step = QUIET_ALLOWED - Duration::from_secs(1);
        assert!(door.admits(Some(&ticket), start + step));
        assert!(door.admits(Some(&ticket), start + step * 2));
        assert!(
            !door.admits(Some(&ticket), start + step * 2 + QUIET_ALLOWED),
            "silent too long"
        );
    }

    #[test]
    fn only_a_local_name_is_answered() {
        for host in [
            "127.0.0.1:8765",
            "localhost:8765",
            "localhost",
            "[::1]:9000",
        ] {
            assert!(named_locally(Some(host)), "{host}");
        }
        for host in [
            "console.example:8765",
            "127.0.0.1.example:8765",
            "[::2]:8765",
            "",
        ] {
            assert!(!named_locally(Some(host)), "{host}");
        }
        assert!(!named_locally(None));
    }

    /// A directory laid out like the console's, beside a file the console
    /// must never serve.
    fn console_files() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("web");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("index.html"), "<!doctype html><title>t</title>").unwrap();
        std::fs::write(root.join("src/app.js"), "export {};").unwrap();
        std::fs::write(root.join("a b.css"), "body{}").unwrap();
        std::fs::write(root.join(".hidden"), "kept-out").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "kept-out").unwrap();
        let root = root.canonicalize().unwrap();
        (dir, root)
    }

    #[test]
    fn a_path_names_a_file_inside_the_directory_or_nothing() {
        let (_dir, root) = console_files();
        assert_eq!(file_under(&root, "/"), Some(root.join("index.html")));
        assert_eq!(
            file_under(&root, "/index.html"),
            Some(root.join("index.html"))
        );
        assert_eq!(
            file_under(&root, "/src/app.js"),
            Some(root.join("src").join("app.js"))
        );
        assert_eq!(file_under(&root, "/a%20b.css"), Some(root.join("a b.css")));
        for path in [
            "/../secret.txt",
            "/..%2Fsecret.txt",
            "/%2e%2e/secret.txt",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/src/../../secret.txt",
            "/src%2F..%2F..%2Fsecret.txt",
            "/..\\secret.txt",
            "/.hidden",
            "/src",
            "/src/",
            "//index.html",
            "/missing.js",
            "/%zz",
            "/%2",
            "/%ff",
            "index.html",
        ] {
            assert_eq!(file_under(&root, path), None, "{path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_directory_is_not_followed() {
        let (dir, root) = console_files();
        std::os::unix::fs::symlink(dir.path().join("secret.txt"), root.join("out.txt")).unwrap();
        assert_eq!(file_under(&root, "/out.txt"), None);
    }

    #[test]
    fn a_file_is_served_as_what_it_is() {
        for (name, kind) in [
            ("index.html", "text/html; charset=utf-8"),
            ("app.js", "text/javascript; charset=utf-8"),
            ("app.css", "text/css; charset=utf-8"),
            ("mark.svg", "image/svg+xml"),
            ("app.webmanifest", "application/manifest+json"),
            ("text.woff2", "font/woff2"),
            ("notes.bin", "application/octet-stream"),
            ("bare", "application/octet-stream"),
        ] {
            assert_eq!(kind_of(Path::new(name)), kind, "{name}");
        }
    }

    #[tokio::test]
    async fn the_console_is_listened_for_on_this_machine_only() {
        let listener = listen(0).await.unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn a_console_needs_a_directory() {
        let (dir, root) = console_files();
        let made = |files: &Path| Console::over(files, helper("http://127.0.0.1:1", machine()));
        assert!(made(&root).is_ok());
        assert!(made(&root.join("index.html")).is_err());
        assert!(made(&dir.path().join("nowhere")).is_err());
    }

    /// One request the way a browser makes it: the head and the body of the
    /// answer.
    async fn ask(port: u16, request: String) -> (String, String) {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.unwrap();
        let answer = String::from_utf8(answer).unwrap();
        let (head, body) = answer.split_once("\r\n\r\n").unwrap();
        (head.to_string(), body.to_string())
    }

    fn get(port: u16, path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
    }

    /// A call the way the page makes it, with the ticket it holds if any.
    fn post(port: u16, path: &str, ticket: Option<&str>, method: &str, params: Value) -> String {
        let body =
            json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }).to_string();
        let ticket = ticket
            .map(|ticket| format!("{TICKET_HEADER}: {ticket}\r\n"))
            .unwrap_or_default();
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost:{port}\r\ncontent-type: application/json\r\n{ticket}content-length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// The console over `root` and a stand-in node, listening: its port and
    /// its ticket.
    async fn serving(root: &Path) -> (u16, String) {
        let node = node_answering(&[("web3_clientVersion", r#""tenzro/0.2.2""#)]).await;
        let console = Console::over(root, helper(&node, machine())).unwrap();
        let listener = listen(0).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ticket = console.door().ticket.clone();
        assert_eq!(
            console.link(port),
            format!("http://127.0.0.1:{port}/#t={ticket}")
        );
        tokio::spawn(serve(listener, console));
        (port, ticket)
    }

    #[tokio::test]
    async fn the_page_and_its_files_are_served_and_nothing_else() {
        let (_dir, root) = console_files();
        let (port, _) = serving(&root).await;

        let (head, body) = ask(port, get(port, "/")).await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("content-type: text/html; charset=utf-8"));
        assert!(head.contains("cache-control: no-store"));
        assert!(head.contains("x-content-type-options: nosniff"));
        assert_eq!(body, "<!doctype html><title>t</title>");

        let (head, body) = ask(port, get(port, "/src/app.js?v=2")).await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("content-type: text/javascript; charset=utf-8"));
        assert_eq!(body, "export {};");

        for path in [
            "/..%2Fsecret.txt",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/.hidden",
            "/missing.js",
            "/control",
            "/rpc",
        ] {
            let (head, body) = ask(port, get(port, path)).await;
            assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"), "{path}");
            assert!(!body.contains("kept-out"), "{path}: {body}");
        }

        let (head, _) = ask(
            port,
            format!("GET / HTTP/1.1\r\nHost: console.example:{port}\r\n\r\n"),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");

        let (head, _) = ask(
            port,
            format!("PUT /index.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        )
        .await;
        assert!(
            head.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn the_conditions_are_listed_only_to_the_page_that_signed_in() {
        let (_dir, root) = console_files();
        let node = node_answering(&[(
            "tenzro_listConditions",
            r#"[{"id":"follow","kind":"follow"}]"#,
        )])
        .await;
        let console = Console::over(&root, helper(&node, machine())).unwrap();
        let listener = listen(0).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ticket = console.door().ticket.clone();
        tokio::spawn(serve(listener, console));
        let list = |ticket: Option<&str>| {
            let request = post(
                port,
                "/control",
                ticket,
                "control_listConditions",
                json!({}),
            );
            async move { serde_json::from_str::<Value>(&ask(port, request).await.1).unwrap() }
        };
        let refused = |answer: Value| {
            assert_eq!(answer["error"]["code"], NOT_SIGNED_IN, "{answer}");
            assert!(answer.get("result").is_none(), "{answer}");
        };

        // Nothing is listed before the page signs in, with or without the ticket.
        refused(list(None).await);
        refused(list(Some(&ticket)).await);
        let request = post(
            port,
            "/control",
            None,
            "control_session",
            json!({ "ticket": ticket }),
        );
        ask(port, request).await;
        // Signed in, a call without the ticket is still refused.
        refused(list(None).await);
        assert_eq!(
            list(Some(&ticket)).await["result"],
            json!([{ "id": "follow", "kind": "follow" }])
        );
    }

    #[tokio::test]
    async fn one_page_signs_in_and_calls_the_helper_and_the_node() {
        let (_dir, root) = console_files();
        let (port, ticket) = serving(&root).await;
        let call =
            |path: &'static str, ticket: Option<&str>, method: &'static str, params: Value| {
                let request = post(port, path, ticket, method, params);
                async move {
                    let (head, body) = ask(port, request).await;
                    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
                    assert!(head.contains("content-type: application/json"), "{head}");
                    serde_json::from_str::<Value>(&body).unwrap()
                }
            };
        let refused = |answer: &Value| {
            assert_eq!(answer["id"], 7);
            assert_eq!(answer["error"]["code"], NOT_SIGNED_IN, "{answer}");
            assert!(answer.get("result").is_none(), "{answer}");
        };

        // Before sign-in nothing is answered, with or without the ticket.
        refused(&call("/control", None, "control_summary", json!([])).await);
        refused(&call("/control", Some(&ticket), "control_summary", json!([])).await);
        refused(&call("/rpc", Some(&ticket), "web3_clientVersion", json!([])).await);
        refused(
            &call(
                "/control",
                None,
                "control_session",
                json!({ "ticket": "0000" }),
            )
            .await,
        );
        refused(&call("/control", None, "control_session", json!([])).await);

        let session = call(
            "/control",
            None,
            "control_session",
            json!({ "ticket": ticket }),
        )
        .await;
        assert_eq!(
            session,
            json!({ "jsonrpc": "2.0", "id": 7, "result": { "operator": true, "expires_in_secs": 900 } })
        );
        refused(
            &call(
                "/control",
                None,
                "control_session",
                json!({ "ticket": ticket }),
            )
            .await,
        );

        // Signed in: the helper answers its own methods, the node the rest.
        let summary = call("/control", Some(&ticket), "control_summary", json!([])).await;
        assert!(summary["result"].is_object(), "{summary}");
        let unknown = call(
            "/control",
            Some(&ticket),
            "control_ceremonyStatus",
            json!({ "id": "c0" }),
        )
        .await;
        assert_eq!(
            unknown["error"],
            json!({ "code": -32602, "message": "No such ceremony" })
        );
        let version = call("/rpc", Some(&ticket), "web3_clientVersion", json!([])).await;
        assert_eq!(
            version,
            json!({ "jsonrpc": "2.0", "id": 7, "result": "tenzro/0.2.2" })
        );
        // Only the node's reads pass, here as on the socket.
        let stop = call("/rpc", Some(&ticket), "tenzro_restartNode", json!([])).await;
        assert_eq!(stop["error"]["code"], -32000);
        assert!(stop.get("result").is_none());

        // A message without an id asks for no answer and gets an empty one.
        let unasked = r#"{"jsonrpc":"2.0","method":"control_summary"}"#;
        let (head, body) = ask(
            port,
            format!(
                "POST /control HTTP/1.1\r\nHost: localhost:{port}\r\n{TICKET_HEADER}: {ticket}\r\ncontent-length: {}\r\n\r\n{unasked}",
                unasked.len()
            ),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 204 "), "{head}");
        assert!(body.is_empty());

        // Without the ticket, or with another, the page is not the one.
        refused(&call("/control", None, "control_summary", json!([])).await);
        refused(&call("/rpc", Some("0000"), "web3_clientVersion", json!([])).await);

        // Each path carries its own methods only.
        for (path, method) in [
            ("/rpc", "control_summary"),
            ("/control", "web3_clientVersion"),
        ] {
            let (head, _) = ask(port, post(port, path, Some(&ticket), method, json!([]))).await;
            assert!(
                head.starts_with("HTTP/1.1 404 Not Found\r\n"),
                "{path} {method}: {head}"
            );
        }
        let (head, _) = ask(
            port,
            post(
                port,
                "/other",
                Some(&ticket),
                "web3_clientVersion",
                json!([]),
            ),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"), "{head}");
    }

    #[tokio::test]
    async fn the_console_answers_so_many_connections_at_once_and_no_more() {
        let (_dir, root) = console_files();
        let (port, _ticket) = serving(&root).await;
        let open = || TcpStream::connect((Ipv4Addr::LOCALHOST, port));
        let mut seated = Vec::new();
        for _ in 0..MOST_CONNECTIONS {
            seated.push(open().await.unwrap());
        }

        let mut one_more = open().await.unwrap();
        let mut answer = Vec::new();
        let _ = one_more.read_to_end(&mut answer).await;
        assert!(answer.is_empty());

        // A seat one of them leaves goes to the next to come.
        seated.pop();
        let mut answered = false;
        for _ in 0..100 {
            let mut stream = open().await.unwrap();
            let _ = stream.write_all(get(port, "/").as_bytes()).await;
            answer.clear();
            let _ = stream.read_to_end(&mut answer).await;
            if answer.starts_with(b"HTTP/1.1 ") {
                answered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(answered, "a seat came free");
    }

    #[test]
    fn the_installed_console_is_found_beside_the_binary_links_followed() {
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("lib").join("tenzro");
        std::fs::create_dir_all(install.join("bin")).unwrap();
        std::fs::create_dir_all(install.join("share").join("console")).unwrap();
        let exe = install.join("bin").join("tenzro");
        std::fs::write(&exe, b"").unwrap();

        let missing = console_beside(&exe).unwrap_err().to_string();
        let expected = install
            .canonicalize()
            .unwrap()
            .join("share")
            .join("console");
        assert!(
            missing.contains(&expected.display().to_string()),
            "{missing}"
        );
        assert!(
            missing.ends_with("Pass --web <DIR> to serve them from a folder."),
            "{missing}"
        );

        std::fs::write(
            install.join("share").join("console").join("index.html"),
            b"<!doctype html>",
        )
        .unwrap();
        assert_eq!(console_beside(&exe).unwrap(), expected);

        #[cfg(unix)]
        {
            let bin = root.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            let link = bin.join("tenzro");
            std::os::unix::fs::symlink(&exe, &link).unwrap();
            assert_eq!(console_beside(&link).unwrap(), expected);
        }
        assert!(console_beside(&root.path().join("nothing")).is_err());
    }
}
