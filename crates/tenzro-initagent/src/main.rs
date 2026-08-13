//! `tenzro-initagent` binary — PID 1 inside a Tenzro machine-class microVM.
//!
//! See the crate docs ([`tenzro_initagent`]) for the full contract. This file is
//! the imperative, Linux-only side: mount pseudo-filesystems, bring up
//! networking, read MMDS + `run.json`, assemble the environment, and supervise
//! the app. All the pure decision logic it calls lives in the library and is
//! unit-tested; this glue is only exercised inside a real microVM (it needs
//! `/dev/kvm`-booted Linux, MMDS, and to actually be PID 1), so it is not part
//! of the test suite.

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "tenzro-initagent is a Linux microVM init (PID 1); it does nothing on this platform"
        );
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Duration;

    use tenzro_initagent::{assemble_env, parse_mmds, parse_run_json, unseal_all};
    use tenzro_initagent::mmds::{MMDS_ADDR, MMDS_TOKEN_PATH, MMDS_TOKEN_TTL_SECS};

    const RUN_JSON_PATH: &str = "/etc/tenzro/run.json";
    /// Optional guest sealing key (32 raw bytes) for guest-side unsealing. Absent
    /// in the default node flow, where the host pre-unseals into MMDS `env`.
    const GUEST_KEY_PATH: &str = "/etc/tenzro/sealing.key";

    /// The current app child pid, for the signal-forwarding handler. 0 = none.
    static APP_PID: AtomicI32 = AtomicI32::new(0);

    pub fn run() {
        // As PID 1 a panic would kernel-panic the guest; keep going and log.
        if let Err(e) = mount_pseudo_filesystems() {
            eprintln!("initagent: mount: {e}");
        }
        if let Err(e) = bring_up_loopback() {
            eprintln!("initagent: loopback: {e}");
        }
        // eth0 is already addressed by the kernel from the `ip=` boot cmdline the
        // supervisor set; nothing to do here beyond loopback.

        install_signal_forwarding();

        let run_spec = match std::fs::read(RUN_JSON_PATH).map_err(|e| e.to_string()).and_then(|b| {
            parse_run_json(&b).map_err(|e| e.to_string())
        }) {
            Ok(s) => s,
            Err(e) => fatal(&format!("run.json ({RUN_JSON_PATH}): {e}")),
        };

        let (mmds_env, sealed_env) = fetch_mmds().unwrap_or_else(|e| {
            eprintln!("initagent: MMDS unavailable ({e}); continuing with empty env");
            (BTreeMap::new(), Vec::new())
        });

        // Guest-side unseal only if a key was delivered; otherwise the host
        // already unsealed into `mmds_env`.
        let unsealed = if !sealed_env.is_empty() {
            match std::fs::read(GUEST_KEY_PATH) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    match unseal_all(&key, &sealed_env) {
                        Ok(v) => v,
                        Err(e) => fatal(&format!("sealed_env unseal: {e}")),
                    }
                }
                Ok(_) => fatal("guest sealing key present but not 32 bytes"),
                Err(e) => fatal(&format!(
                    "sealed_env delivered but no guest key at {GUEST_KEY_PATH}: {e}"
                )),
            }
        } else {
            Vec::new()
        };

        let env = assemble_env(&mmds_env, &unsealed, run_spec.port);

        if let Some(port) = run_spec.port {
            start_health_server(port);
        }

        supervise(&run_spec, &env);
    }

    /// Mount the kernel pseudo-filesystems an init must provide. Best-effort per
    /// mount: a rootfs that already has one (e.g. `devtmpfs` auto-mounted) makes
    /// the call `EBUSY`, which we ignore.
    fn mount_pseudo_filesystems() -> Result<(), String> {
        // (source, target, fstype, flags)
        let mounts: &[(&str, &str, &str, u64)] = &[
            ("proc", "/proc", "proc", 0),
            ("sysfs", "/sys", "sysfs", 0),
            ("devtmpfs", "/dev", "devtmpfs", 0),
            ("tmpfs", "/tmp", "tmpfs", 0),
            ("tmpfs", "/run", "tmpfs", 0),
        ];
        for (src, target, fstype, flags) in mounts {
            let _ = std::fs::create_dir_all(target);
            let src_c = cstr(src);
            let tgt_c = cstr(target);
            let fs_c = cstr(fstype);
            let rc = unsafe {
                libc::mount(
                    src_c.as_ptr(),
                    tgt_c.as_ptr(),
                    fs_c.as_ptr(),
                    *flags,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                // EBUSY: already mounted — fine.
                if err.raw_os_error() != Some(libc::EBUSY) {
                    eprintln!("initagent: mount {target}: {err}");
                }
            }
        }
        Ok(())
    }

    /// Bring the loopback interface up via an ioctl on a datagram socket. `eth0`
    /// is left to the kernel `ip=` cmdline.
    fn bring_up_loopback() -> Result<(), String> {
        const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
        const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
        // struct ifreq: 16-byte name followed by a union; lay it out as bytes.
        const IFREQ_SIZE: usize = 40;
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut ifreq = [0u8; IFREQ_SIZE];
        ifreq[..2].copy_from_slice(b"lo");
        let ret = (|| -> Result<(), String> {
            if unsafe { libc::ioctl(fd, SIOCGIFFLAGS, ifreq.as_mut_ptr()) } != 0 {
                return Err(format!("SIOCGIFFLAGS: {}", std::io::Error::last_os_error()));
            }
            // flags are a c_short at offset 16 (right after the 16-byte name).
            let mut flags = i16::from_ne_bytes([ifreq[16], ifreq[17]]);
            flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            ifreq[16..18].copy_from_slice(&flags.to_ne_bytes());
            if unsafe { libc::ioctl(fd, SIOCSIFFLAGS, ifreq.as_ptr()) } != 0 {
                return Err(format!("SIOCSIFFLAGS: {}", std::io::Error::last_os_error()));
            }
            Ok(())
        })();
        unsafe { libc::close(fd) };
        ret
    }

    /// MMDS v2: PUT a token, then GET the document with it. Returns the plaintext
    /// env map and any sealed entries.
    fn fetch_mmds() -> Result<(BTreeMap<String, String>, Vec<tenzro_initagent::SealedEnvVar>), String>
    {
        let addr = format!("{MMDS_ADDR}:80");
        let sock = addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("no MMDS address")?;

        let token = mmds_token(&sock)?;
        let body = mmds_get(&sock, "/", &token)?;
        let data = parse_mmds(&body)?;
        Ok((data.env, data.sealed_env))
    }

    fn mmds_token(sock: &std::net::SocketAddr) -> Result<String, String> {
        let req = format!(
            "PUT {MMDS_TOKEN_PATH} HTTP/1.1\r\nHost: {MMDS_ADDR}\r\nX-metadata-token-ttl-seconds: {MMDS_TOKEN_TTL_SECS}\r\nConnection: close\r\n\r\n",
        );
        let (status, body) = http_roundtrip(sock, req.as_bytes())?;
        if status != 200 {
            return Err(format!("token request returned {status}"));
        }
        Ok(String::from_utf8_lossy(&body).trim().to_string())
    }

    fn mmds_get(sock: &std::net::SocketAddr, path: &str, token: &str) -> Result<Vec<u8>, String> {
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {MMDS_ADDR}\r\nX-metadata-token: {token}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        );
        let (status, body) = http_roundtrip(sock, req.as_bytes())?;
        if status != 200 {
            return Err(format!("GET {path} returned {status}"));
        }
        Ok(body)
    }

    /// Minimal HTTP/1.1 client: send a request, return `(status, body)`. No
    /// dependency — the request set is tiny and fixed.
    fn http_roundtrip(
        sock: &std::net::SocketAddr,
        req: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let mut stream =
            TcpStream::connect_timeout(sock, Duration::from_secs(2)).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        stream.write_all(req).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).map_err(|e| e.to_string())?;
        let split = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("malformed HTTP response")?;
        let head = String::from_utf8_lossy(&resp[..split]);
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or("no HTTP status")?;
        Ok((status, resp[split + 4..].to_vec()))
    }

    /// Fork/exec the app and supervise it: reap all children (PID 1's duty),
    /// restart the app on exit with capped backoff.
    fn supervise(run_spec: &tenzro_initagent::RunSpec, env: &[(String, String)]) -> ! {
        let (uid, gid) = run_spec
            .user
            .as_deref()
            .and_then(resolve_user)
            .unwrap_or((0, 0));

        let mut backoff = Duration::from_millis(200);
        loop {
            let mut cmd = Command::new(&run_spec.cmd[0]);
            cmd.args(&run_spec.cmd[1..]);
            cmd.current_dir(&run_spec.cwd);
            cmd.env_clear();
            for (k, v) in env {
                cmd.env(k, v);
            }
            if uid != 0 || gid != 0 {
                cmd.uid(uid).gid(gid);
            }

            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("initagent: spawn {:?}: {e}", run_spec.cmd);
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                    continue;
                }
            };
            let app_pid = child.id() as i32;
            APP_PID.store(app_pid, Ordering::SeqCst);
            // Intentionally do not `wait()` on `child`; PID 1 reaps everything
            // (including this child) via `waitpid(-1)` below so orphaned
            // grandchildren don't become permanent zombies.
            std::mem::forget(child);

            let started = std::time::Instant::now();
            let exited = reap_until(app_pid);
            APP_PID.store(0, Ordering::SeqCst);
            eprintln!("initagent: app pid {app_pid} exited ({exited}); restarting");

            // Reset backoff if the app ran for a healthy while.
            if started.elapsed() > Duration::from_secs(30) {
                backoff = Duration::from_millis(200);
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(10));
        }
    }

    /// Reap every child that exits until the tracked app pid is reaped; returns a
    /// human string describing how the app exited. Orphaned grandchildren
    /// reparented to PID 1 are reaped and ignored here.
    fn reap_until(app_pid: i32) -> String {
        loop {
            let mut status: libc::c_int = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
            if pid < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return format!("waitpid error: {err}");
            }
            if pid == app_pid {
                if libc::WIFEXITED(status) {
                    return format!("code {}", libc::WEXITSTATUS(status));
                } else if libc::WIFSIGNALED(status) {
                    return format!("signal {}", libc::WTERMSIG(status));
                }
                return "unknown".into();
            }
            // Some other (orphaned) child — reaped, ignore.
        }
    }

    /// Forward SIGTERM/SIGINT to the app so a graceful node-side stop propagates.
    fn install_signal_forwarding() {
        unsafe {
            libc::signal(libc::SIGTERM, forward_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, forward_signal as *const () as libc::sighandler_t);
        }
    }

    extern "C" fn forward_signal(sig: libc::c_int) {
        let pid = APP_PID.load(Ordering::SeqCst);
        if pid > 0 {
            unsafe { libc::kill(pid, sig) };
        }
    }

    /// A tiny `/health` responder on `127.0.0.1:<port+1>` reporting whether the
    /// app child is currently running. Runs on its own thread; failures to bind
    /// are logged and non-fatal.
    fn start_health_server(app_port: u16) {
        let health_port = app_port.wrapping_add(1);
        std::thread::spawn(move || {
            let listener = match std::net::TcpListener::bind(("127.0.0.1", health_port)) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("initagent: health bind :{health_port}: {e}");
                    return;
                }
            };
            for stream in listener.incoming().flatten() {
                let up = APP_PID.load(Ordering::SeqCst) > 0;
                let (code, ok) = if up { ("200 OK", "ok") } else { ("503 Service Unavailable", "down") };
                let body = format!("{{\"status\":\"{ok}\"}}");
                let resp = format!(
                    "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut s = stream;
                let _ = s.write_all(resp.as_bytes());
            }
        });
    }

    /// Resolve a user name to `(uid, gid)` by parsing `/etc/passwd`. Returns
    /// `None` if the file or user is absent (caller falls back to root).
    fn resolve_user(name: &str) -> Option<(u32, u32)> {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let mut f = line.split(':');
            if f.next() == Some(name) {
                let _pw = f.next();
                let uid = f.next()?.parse().ok()?;
                let gid = f.next()?.parse().ok()?;
                return Some((uid, gid));
            }
        }
        None
    }

    fn cstr(s: &str) -> std::ffi::CString {
        std::ffi::CString::new(s).expect("no interior NUL in a static path")
    }

    fn fatal(msg: &str) -> ! {
        eprintln!("initagent: FATAL: {msg}");
        // As PID 1, exiting triggers a kernel panic (panic=1 reboots). Pause
        // briefly so the message flushes to the serial console first.
        std::thread::sleep(Duration::from_millis(200));
        std::process::exit(1);
    }
}
