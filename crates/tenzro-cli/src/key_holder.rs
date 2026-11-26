//! Keys held in another machine's TPM, reached through a local key holder.
//!
//! A machine with no TPM runs `tenzro-node tpm key-holder`, which carries
//! signing requests over a Unix socket to the machine that owns the TPM. A
//! node started with `--tpm-key-holder` (or `TENZRO_TPM_KEY_HOLDER`) signs
//! that way; this module gives the CLI the same reach, so `tenzro validator
//! register-machine` and the other commands that sign as the node or the
//! machine identity work on that machine too. The CLI does not link the node
//! crate, so the few lines of the holder framing live here.
//!
//! Configured by the same two variables the node reads:
//! `TENZRO_TPM_KEY_HOLDER` (the socket) and `TENZRO_TPM_LABEL` (the key label
//! the provider enrolled for this machine).

use anyhow::{Result, anyhow};

/// The environment variable naming the key holder socket.
pub const SOCKET_VAR: &str = "TENZRO_TPM_KEY_HOLDER";
/// The environment variable naming the enrolled key label.
pub const LABEL_VAR: &str = "TENZRO_TPM_LABEL";

static ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this process signs through a key holder.
pub fn active() -> bool {
    ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// The socket and label named by `socket` and `label` values, when the socket
/// is set and not empty. A socket with no label is an error: the provider
/// holds keys under the label it enrolled.
pub fn parse(socket: Option<&str>, label: Option<&str>) -> Result<Option<(String, String)>> {
    let Some(socket) = socket.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let label = label.map(str::trim).filter(|l| !l.is_empty()).ok_or_else(|| {
        anyhow!("{SOCKET_VAR} is set but {LABEL_VAR} is not: set it to the key label the provider enrolled for this machine")
    })?;
    Ok(Some((socket.to_string(), label.to_string())))
}

/// Routes every hardware key this process opens to the key holder named by the
/// environment, when it is set and this machine has no TPM of its own to
/// prefer. Returns whether it did. Call once, before any key use.
pub fn install_from_env() -> Result<bool> {
    let socket = std::env::var(SOCKET_VAR).ok();
    let label = std::env::var(LABEL_VAR).ok();
    let Some((socket, label)) = parse(socket.as_deref(), label.as_deref())? else {
        return Ok(false);
    };
    install(std::path::PathBuf::from(socket), label)?;
    Ok(true)
}

#[cfg(unix)]
mod unix {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Result, anyhow};
    use tenzro_device_key::DeviceKeyError;
    use tenzro_device_key::HardwareSigner;
    use tenzro_device_key::remote::{RemoteDeriveClient, RemoteTpmSigner, Transport};

    /// The key holder's operation that carries one signing request.
    const OP_CALL: u8 = 1;
    const STATUS_OK: u8 = 0;
    const MAX_FRAME: usize = 4 * 1024 * 1024;
    const TIMEOUT: Duration = Duration::from_secs(90);

    #[derive(Debug, Clone)]
    struct HolderTransport {
        socket: PathBuf,
    }

    impl Transport for HolderTransport {
        fn call(&self, request: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
            request_holder(&self.socket, OP_CALL, request)
                .map_err(|e| DeviceKeyError::Tpm(format!("remote TPM: {e}")))
        }
    }

    /// One operation to the key holder at `socket`: `[op][len u32 BE][payload]`
    /// out, `[status][len u32 BE][body]` back.
    pub(super) fn request_holder(
        socket: &Path,
        op: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| {
            format!(
                "the key holder at {} is not reachable: {e}",
                socket.display()
            )
        })?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
            .map_err(|e| format!("key holder socket: {e}"))?;
        let mut out = vec![op];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        stream
            .write_all(&out)
            .map_err(|e| format!("key holder socket: {e}"))?;
        let mut head = [0u8; 5];
        stream
            .read_exact(&mut head)
            .map_err(|e| format!("the key holder did not answer: {e}"))?;
        let len = u32::from_be_bytes(head[1..5].try_into().expect("four bytes")) as usize;
        if len > MAX_FRAME {
            return Err("the key holder's answer is too large".into());
        }
        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .map_err(|e| format!("the key holder did not answer: {e}"))?;
        match head[0] {
            STATUS_OK => Ok(body),
            _ => Err(String::from_utf8_lossy(&body).into_owned()),
        }
    }

    pub(super) fn install(socket: PathBuf, label: String) -> Result<()> {
        let signer_socket = socket.clone();
        let signer_label = label.clone();
        tenzro_device_key::signer::use_remote_signers(Box::new(move |key| {
            let signer = RemoteTpmSigner::open(
                HolderTransport {
                    socket: signer_socket.clone(),
                },
                &format!("{signer_label}/{key}"),
            )?;
            Ok(Box::new(signer) as Box<dyn HardwareSigner>)
        }))
        .map_err(|e| anyhow!("{e}"))?;
        tenzro_device_key::derive::use_remote_root(Arc::new(RemoteDeriveClient::new(
            HolderTransport { socket },
            &label,
        )))
        .map_err(|e| anyhow!("{e}"))
    }
}

#[cfg(unix)]
fn install(socket: std::path::PathBuf, label: String) -> Result<()> {
    unix::install(socket, label)?;
    ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

#[cfg(not(unix))]
fn install(_socket: std::path::PathBuf, _label: String) -> Result<()> {
    Err(anyhow!(
        "{SOCKET_VAR} needs a Unix socket, which this platform does not have"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_socket_is_no_key_holder() {
        assert!(parse(None, Some("l")).unwrap().is_none());
        assert!(parse(Some("  "), Some("l")).unwrap().is_none());
    }

    #[test]
    fn socket_without_label_is_refused_by_name() {
        let e = parse(Some("/run/kh.sock"), None).unwrap_err().to_string();
        assert!(e.contains(LABEL_VAR), "{e}");
    }

    #[test]
    fn socket_and_label_are_taken_trimmed() {
        assert_eq!(
            parse(Some(" /run/kh.sock "), Some("d1 ")).unwrap(),
            Some(("/run/kh.sock".into(), "d1".into()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn framing_round_trips_and_surfaces_a_refusal() {
        use std::io::{Read, Write};
        let dir = std::env::temp_dir().join(format!("kh-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("kh.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            for status in [0u8, 1u8] {
                let (mut s, _) = listener.accept().unwrap();
                let mut head = [0u8; 5];
                s.read_exact(&mut head).unwrap();
                let n = u32::from_be_bytes(head[1..5].try_into().unwrap()) as usize;
                let mut body = vec![0u8; n];
                s.read_exact(&mut body).unwrap();
                let reply: &[u8] = if status == 0 { &body } else { b"not allowed" };
                let mut out = vec![status];
                out.extend_from_slice(&(reply.len() as u32).to_be_bytes());
                out.extend_from_slice(reply);
                s.write_all(&out).unwrap();
            }
        });
        assert_eq!(unix::request_holder(&sock, 1, b"hello").unwrap(), b"hello");
        assert_eq!(
            unix::request_holder(&sock, 1, b"x").unwrap_err(),
            "not allowed"
        );
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            unix::request_holder(&sock, 1, b"x")
                .unwrap_err()
                .contains("not reachable")
        );
    }
}
