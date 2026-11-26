//! The helper's local socket: a Unix socket on Linux and macOS, a named pipe
//! on Windows, open to the user who started the helper and nobody else. Each
//! connection carries JSON-RPC, one message per line, for as long as it stays
//! open.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;

use super::{Helper, INVALID_REQUEST, REFUSED, unasked};
pub(crate) use local::{bind, serve};

/// How long the server waits before it listens again after a failed accept.
pub(super) const ACCEPT_PAUSE: Duration = Duration::from_millis(200);

/// How long a turned-away connection stays open for its refusal to be read.
const REFUSAL_WAIT: Duration = Duration::from_secs(5);

/// The longest request line the helper reads, in bytes, not counting its end.
pub(super) const LONGEST_LINE: u64 = 1 << 20;

/// How long a connection may go without sending a whole request line before
/// the helper closes it, so silent connections cannot keep every seat.
pub(super) const LONGEST_SILENCE: Duration = Duration::from_secs(30);

/// How many connections the helper answers at once.
pub(super) const MOST_CONNECTIONS: usize = 32;

/// Where the apps look for the helper on this machine.
pub(crate) fn default_socket() -> PathBuf {
    #[cfg(unix)]
    {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR");
        local::socket_path(
            cfg!(target_os = "macos"),
            runtime_dir.as_deref(),
            &tenzro_types::paths::tenzro_home(),
        )
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\tenzro-control")
    }
}

/// Listens at `at` and answers until the process is told to stop.
pub(crate) async fn run(at: &Path, helper: Arc<Helper>) -> Result<()> {
    let bound = bind(at)?;
    crate::output::print_info(&format!("Listening on {}", at.display()));
    tokio::select! {
        () = serve(bound, helper) => {}
        () = stopped() => {}
    }
    Ok(())
}

/// Resolves when the process is interrupted or asked to end.
pub(super) async fn stopped() {
    let interrupted = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).ok();
        let ended = async {
            match term.as_mut() {
                Some(term) => {
                    term.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = interrupted => {}
            () = ended => {}
        }
    }
    #[cfg(windows)]
    interrupted.await;
}

/// Answers every line of one connection until the other side closes it, or
/// sends a line longer than the helper reads.
async fn converse<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    helper: Arc<Helper>,
    silence: Duration,
) {
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    let mut line = Vec::new();
    loop {
        line.clear();
        let mut limited = (&mut read).take(LONGEST_LINE + 1);
        let taken = limited.read_until(b'\n', &mut line);
        if !matches!(tokio::time::timeout(silence, taken).await, Ok(Ok(1..))) {
            break;
        }
        let whole = line.ends_with(b"\n") || line.len() as u64 <= LONGEST_LINE;
        let answer = if !whole {
            Some(unasked(
                INVALID_REQUEST,
                "The request line is longer than the helper reads.",
            ))
        } else if line.trim_ascii().is_empty() {
            None
        } else {
            helper.answer(&line).await
        };
        if let Some(mut answer) = answer {
            answer.push('\n');
            // A client that asks and never reads would otherwise hold its
            // seat forever on a full socket buffer.
            let written = tokio::time::timeout(silence, write.write_all(answer.as_bytes()));
            if !matches!(written.await, Ok(Ok(()))) {
                break;
            }
        }
        if !whole {
            break;
        }
    }
}

/// One seat for each connection the helper answers at once.
fn seats() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MOST_CONNECTIONS))
}

/// Answers a new connection for as long as it stays open; while every seat is
/// taken, tells it so and closes it.
async fn admit<S>(mut stream: S, seats: &Arc<Semaphore>, helper: &Arc<Helper>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match seats.clone().try_acquire_owned() {
        Ok(seat) => {
            let helper = helper.clone();
            tokio::spawn(async move {
                converse(stream, helper, LONGEST_SILENCE).await;
                drop(seat);
            });
        }
        Err(_) => {
            let mut full = unasked(
                REFUSED,
                "The helper has as many connections open as it answers at once.",
            );
            full.push('\n');
            // A named pipe drops what its client has not read when the
            // helper's end closes, so the refusal stays open until the
            // client has read it and closed, or for the refusal wait. It
            // waits on its own, so the next connection is not held up.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(REFUSAL_WAIT, async {
                    stream.write_all(full.as_bytes()).await?;
                    stream.read(&mut [0u8; 1]).await
                })
                .await;
            });
        }
    }
}

#[cfg(unix)]
mod local {
    use std::ffi::OsStr;
    use std::fs::{DirBuilder, Permissions};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use anyhow::{Context, Result, bail};
    use tokio::net::UnixListener;

    use super::{ACCEPT_PAUSE, Helper, admit, seats};

    /// The socket's place: the user's runtime directory on Linux when the
    /// session has one, otherwise the Tenzro home.
    pub(super) fn socket_path(macos: bool, runtime_dir: Option<&OsStr>, home: &Path) -> PathBuf {
        match runtime_dir.filter(|dir| !macos && !dir.is_empty()) {
            Some(dir) => Path::new(dir).join("tenzro").join("control.sock"),
            None => home.join("control.sock"),
        }
    }

    /// A socket this process listens on. Dropping it takes the socket away.
    pub(crate) struct Bound {
        listener: UnixListener,
        path: PathBuf,
        owner: u32,
        file: (u64, u64),
    }

    impl Drop for Bound {
        fn drop(&mut self) {
            // Another helper may have taken the place since; its socket stays.
            if file_id(&self.path) == Some(self.file) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    fn file_id(path: &Path) -> Option<(u64, u64)> {
        let found = std::fs::symlink_metadata(path).ok()?;
        Some((found.dev(), found.ino()))
    }

    /// Listens at `path`, replacing a socket nothing listens on any more.
    pub(crate) fn bind(path: &Path) -> Result<Bound> {
        if let Ok(found) = std::fs::symlink_metadata(path) {
            if !found.file_type().is_socket() {
                bail!("{} is in the way and is not a socket", path.display());
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("a helper is already listening on {}", path.display());
            }
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        // The socket is made inside a directory no other user can enter and
        // moved into place once its own mode is set, so there is no moment
        // at which another user could open it.
        let nest = parent.join(format!(".c{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&nest);
        let listener = DirBuilder::new()
            .mode(0o700)
            .create(&nest)
            .with_context(|| format!("could not write in {}", parent.display()))
            .and_then(|()| kept_by_this_user(parent, &nest))
            .and_then(|()| {
                listen_through(&nest, path)
                    .with_context(|| format!("could not listen on {}", path.display()))
            });
        let _ = std::fs::remove_dir_all(&nest);
        let listener = listener?;
        let made = std::fs::symlink_metadata(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        Ok(Bound {
            listener,
            path: path.to_path_buf(),
            owner: made.uid(),
            file: (made.dev(), made.ino()),
        })
    }

    /// Refuses a directory in which someone else could put another socket in
    /// this one's place. This process has just made `nest` there, so the
    /// nest's owner is the user the helper runs as.
    fn kept_by_this_user(parent: &Path, nest: &Path) -> Result<()> {
        let ours = std::fs::symlink_metadata(nest)?;
        let theirs = std::fs::metadata(parent)?;
        if theirs.uid() != ours.uid() || theirs.mode() & 0o022 != 0 {
            bail!(
                "{} is not a directory only this user can write in, so someone else could put \
                 a socket of their own in the helper's place. Keep the socket in a directory \
                 that belongs to this user and that neither its group nor anyone else may \
                 write in.",
                parent.display()
            );
        }
        Ok(())
    }

    /// Whether a connection is answered: only one the socket's owner opened.
    fn answered(peer: Option<u32>, owner: u32) -> bool {
        peer == Some(owner)
    }

    fn listen_through(nest: &Path, path: &Path) -> io::Result<UnixListener> {
        let made = nest.join("s");
        let listener = std::os::unix::net::UnixListener::bind(&made)?;
        std::fs::set_permissions(&made, Permissions::from_mode(0o600))?;
        std::fs::rename(&made, path)?;
        listener.set_nonblocking(true)?;
        UnixListener::from_std(listener)
    }

    /// Answers every connection the socket's owner opens.
    pub(crate) async fn serve(bound: Bound, helper: Arc<Helper>) {
        let seats = seats();
        loop {
            let Ok((stream, _)) = bound.listener.accept().await else {
                tokio::time::sleep(ACCEPT_PAUSE).await;
                continue;
            };
            if answered(stream.peer_cred().ok().map(|peer| peer.uid()), bound.owner) {
                admit(stream, &seats, &helper).await;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::commands::control::tests::private_dir;

        fn mode(path: &Path) -> u32 {
            std::fs::symlink_metadata(path).unwrap().mode() & 0o777
        }

        #[test]
        fn the_socket_sits_where_each_platform_keeps_it() {
            let home = Path::new("/home/a/.tenzro");
            assert_eq!(
                socket_path(false, Some(OsStr::new("/run/user/1000")), home),
                Path::new("/run/user/1000/tenzro/control.sock")
            );
            assert_eq!(
                socket_path(false, None, home),
                Path::new("/home/a/.tenzro/control.sock")
            );
            assert_eq!(
                socket_path(false, Some(OsStr::new("")), home),
                Path::new("/home/a/.tenzro/control.sock")
            );
            assert_eq!(
                socket_path(true, Some(OsStr::new("/run/user/1000")), home),
                Path::new("/home/a/.tenzro/control.sock")
            );
        }

        #[tokio::test]
        async fn the_socket_is_its_owners_alone() {
            let dir = private_dir();
            let at = dir.path().join("made").join("control.sock");
            let bound = bind(&at).unwrap();

            assert_eq!(mode(&at), 0o600);
            assert_eq!(mode(at.parent().unwrap()), 0o700);
            assert_eq!(
                bound.owner,
                std::fs::metadata(dir.path()).unwrap().uid(),
                "the socket belongs to the user who made it"
            );
            let beside: Vec<_> = std::fs::read_dir(at.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(beside, ["control.sock"]);
        }

        #[tokio::test]
        async fn a_second_helper_is_refused_while_one_listens() {
            let dir = private_dir();
            let at = dir.path().join("control.sock");
            let first = bind(&at).unwrap();

            let second = bind(&at).err().unwrap().to_string();
            assert!(second.contains("already listening"), "{second}");
            assert_eq!(file_id(&at), Some(first.file));

            drop(first);
            assert!(!at.exists(), "a helper that stops takes its socket away");
        }

        #[tokio::test]
        async fn a_socket_nothing_listens_on_is_replaced() {
            let dir = private_dir();
            let at = dir.path().join("control.sock");
            drop(std::os::unix::net::UnixListener::bind(&at).unwrap());
            let left = file_id(&at).unwrap();

            let bound = bind(&at).unwrap();
            assert_ne!(bound.file, left);
            assert_eq!(mode(&at), 0o600);
            assert!(std::os::unix::net::UnixStream::connect(&at).is_ok());
        }

        #[tokio::test]
        async fn a_file_that_is_no_socket_is_left_alone() {
            let dir = private_dir();
            let at = dir.path().join("control.sock");
            std::fs::write(&at, "kept").unwrap();

            let refused = bind(&at).err().unwrap().to_string();
            assert!(refused.contains("not a socket"), "{refused}");
            assert_eq!(std::fs::read_to_string(&at).unwrap(), "kept");
        }

        #[test]
        fn only_the_sockets_owner_is_answered() {
            assert!(answered(Some(1000), 1000));
            assert!(!answered(Some(1001), 1000));
            assert!(!answered(Some(0), 1000));
            assert!(!answered(None, 1000));
        }

        #[tokio::test]
        async fn a_directory_others_may_write_in_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let shared = dir.path().join("shared");
            std::fs::create_dir(&shared).unwrap();
            let at = shared.join("control.sock");
            for loose in [0o770, 0o707, 0o720, 0o1777] {
                std::fs::set_permissions(&shared, Permissions::from_mode(loose)).unwrap();
                let refused = bind(&at)
                    .err()
                    .expect("no socket where another user may write")
                    .to_string();
                assert!(refused.contains("only this user"), "{loose:o}: {refused}");
                assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 0, "{loose:o}");
            }
            std::fs::set_permissions(&shared, Permissions::from_mode(0o755)).unwrap();
            assert!(bind(&at).is_ok());
        }

        #[tokio::test]
        async fn a_link_at_the_path_is_left_alone() {
            let dir = private_dir();
            let elsewhere = dir.path().join("elsewhere.sock");
            let _listening = std::os::unix::net::UnixListener::bind(&elsewhere).unwrap();
            let at = dir.path().join("control.sock");
            // A link to a socket something listens on, and a link to nothing.
            for target in [elsewhere.clone(), dir.path().join("nothing")] {
                std::os::unix::fs::symlink(&target, &at).unwrap();
                let refused = bind(&at).err().expect("a link is not a socket").to_string();
                assert!(refused.contains("is not a socket"), "{refused}");
                assert_eq!(std::fs::read_link(&at).unwrap(), target);
                std::fs::remove_file(&at).unwrap();
            }
            assert!(
                std::fs::symlink_metadata(&elsewhere)
                    .unwrap()
                    .file_type()
                    .is_socket()
            );
        }
    }
}

#[cfg(windows)]
mod local {
    use std::ffi::c_void;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{ACCEPT_PAUSE, Helper, admit, seats};

    /// The revision of the security descriptor text format.
    const DESCRIPTOR_TEXT_REVISION: u32 = 1;

    /// The access list every instance of the pipe is made with: the user this
    /// process runs as may do everything, and nobody else is named.
    struct OwnerOnly {
        descriptor_text: Vec<u16>,
    }

    impl OwnerOnly {
        fn for_this_user() -> io::Result<Self> {
            let text = format!("D:P(A;;GA;;;{})", this_user()?);
            Ok(Self {
                descriptor_text: text.encode_utf16().chain(Some(0)).collect(),
            })
        }

        /// Makes one instance of the pipe; `first` refuses a name that
        /// another process already serves.
        fn pipe(&self, name: &Path, first: bool) -> io::Result<NamedPipeServer> {
            let mut descriptor: *mut c_void = std::ptr::null_mut();
            // SAFETY: the text is a NUL-terminated UTF-16 string that outlives
            // the call, and `descriptor` is a valid place for the result.
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    self.descriptor_text.as_ptr(),
                    DESCRIPTOR_TEXT_REVISION,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            if converted == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            // SAFETY: `attributes` is a whole SECURITY_ATTRIBUTES whose
            // descriptor stays allocated until the pipe has been made.
            let pipe = unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .create_with_security_attributes_raw(
                        name,
                        (&raw mut attributes).cast::<c_void>(),
                    )
            };
            // SAFETY: the descriptor was allocated by the conversion above and
            // nothing reads it after this.
            unsafe { LocalFree(descriptor) };
            pipe
        }
    }

    /// The security identifier of the user this process runs as, as text.
    fn this_user() -> io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the process's own pseudo-handle is always valid and `token`
        // is a valid place for the result.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // The answer is a TOKEN_USER followed by the identifier it points at;
        // sixteen u64 hold the largest of both, aligned for the structure.
        let mut user = [0u64; 16];
        let mut written = 0u32;
        // SAFETY: `token` is the open token and the buffer is as long as said.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                user.as_mut_ptr().cast::<c_void>(),
                size_of_val(&user) as u32,
                &mut written,
            )
        };
        let read_error = io::Error::last_os_error();
        // SAFETY: `token` was opened above and is not used again.
        unsafe { CloseHandle(token) };
        if read == 0 {
            return Err(read_error);
        }
        // SAFETY: the call filled the buffer with a TOKEN_USER, for which it
        // is aligned.
        let identifier = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `identifier` points into `user`, which is still alive, and
        // `text` is a valid place for the result.
        if unsafe { ConvertSidToStringSidW(identifier, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: the conversion wrote a NUL-terminated string at `text`.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` code units before the NUL were just read.
        let user = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: the string was allocated by the conversion above and
        // nothing reads it after this.
        unsafe { LocalFree(text.cast::<c_void>()) };
        Ok(user)
    }

    /// A pipe this process serves, with one instance waiting for a caller.
    pub(crate) struct Bound {
        waiting: NamedPipeServer,
        name: PathBuf,
        owner: OwnerOnly,
    }

    /// Serves the pipe `name`, which no other process may be serving.
    pub(crate) fn bind(name: &Path) -> Result<Bound> {
        let owner = OwnerOnly::for_this_user().context("could not read this user's identity")?;
        let waiting = owner.pipe(name, true).with_context(|| {
            format!(
                "could not serve {}; a helper may already be listening",
                name.display()
            )
        })?;
        Ok(Bound {
            waiting,
            name: name.to_path_buf(),
            owner,
        })
    }

    /// Answers every connection made to the pipe.
    pub(crate) async fn serve(bound: Bound, helper: Arc<Helper>) {
        let Bound {
            mut waiting,
            name,
            owner,
        } = bound;
        let seats = seats();
        loop {
            let connected = waiting.connect().await.is_ok();
            // The next instance exists before this one is handed on, so the
            // name is never left unserved.
            let next = loop {
                match owner.pipe(&name, false) {
                    Ok(next) => break next,
                    Err(_) => tokio::time::sleep(ACCEPT_PAUSE).await,
                }
            };
            let stream = std::mem::replace(&mut waiting, next);
            if connected {
                admit(stream, &seats, &helper).await;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_pipe_names_this_user_and_nobody_else() {
            let owner = OwnerOnly::for_this_user().unwrap();
            let text = String::from_utf16(&owner.descriptor_text).unwrap();
            let user = this_user().unwrap();
            assert!(user.starts_with("S-1-"), "{user}");
            assert_eq!(text, format!("D:P(A;;GA;;;{user})\0"));
        }

        #[tokio::test]
        async fn a_second_helper_is_refused_while_one_serves() {
            let name = PathBuf::from(format!(
                r"\\.\pipe\tenzro-control-test-second-{}",
                std::process::id()
            ));
            let _first = bind(&name).unwrap();
            let second = bind(&name).err().unwrap().to_string();
            assert!(second.contains("already be listening"), "{second}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::control::tests::{helper, machine};

    #[tokio::test]
    async fn a_connection_that_falls_silent_is_closed() {
        let helper = helper("http://127.0.0.1:1", machine());
        let silence = Duration::from_millis(200);
        for after_answer in [&b""[..], &br#"{"jsonrpc":"2.0","id":2,"#[..]] {
            let (caller, ours) = tokio::io::duplex(4096);
            let conversing = tokio::spawn(converse(ours, helper.clone(), silence));
            let (read, mut write) = tokio::io::split(caller);
            let mut answers = BufReader::new(read);
            write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"control_nothing\"}\n")
                .await
                .unwrap();
            let mut answer = String::new();
            answers.read_line(&mut answer).await.unwrap();
            assert!(answer.contains("Method not found"), "{answer}");

            // Nothing more, or half a line that never ends.
            write.write_all(after_answer).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), conversing)
                .await
                .expect("the helper closes a silent connection")
                .unwrap();
            answer.clear();
            assert_eq!(answers.read_line(&mut answer).await.unwrap(), 0);
        }
    }
}
