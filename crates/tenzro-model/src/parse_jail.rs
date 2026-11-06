//! Model files are parsed first in a separate, locked-down process.
//!
//! A model file comes from outside the node, and the parsers that read it
//! (llama.cpp's GGUF reader, ONNX Runtime's protobuf reader) are C and C++.
//! Before a model is loaded, its header is parsed by a child process that:
//!
//! * gets the file as its standard input, opened read-only by the node, and
//!   writes a JSON index of what it found to its standard output;
//! * for ONNX, also gets the model's external-data files that sit beside it
//!   (`<model>.data`, `<model>_data`, `<stem>.onnx_data`, `<stem>.onnx.data`,
//!   `<stem>.data`) as further read-only descriptors, since it may not open
//!   them itself;
//! * runs under a memory cap (`RLIMIT_AS`), a CPU-time cap, no core dumps and
//!   no file writes;
//! * on Linux, sets `no_new_privs` and installs a seccomp allow-list before it
//!   reads a byte: it can read, write to its pipes, seek, map and free memory
//!   and exit. Every other call, opening a file or creating a socket among
//!   them, kills it with `SIGSYS`, so it has no network and no filesystem.
//!
//! GGUF headers are read by llama.cpp's own reader. ONNX files are read by
//! ONNX Runtime itself: the child loads the model from memory into a session
//! with one thread and no graph optimisation, which runs ONNX Runtime's
//! protobuf reader over the whole `ModelProto` and its checks of the graph,
//! with the external data handed over in memory. ONNX Runtime is initialised
//! before the lock-down, so only the parse runs under the allow-list.
//!
//! The node accepts the model only when the child exits zero and its index
//! is consistent with the file; a child that crashes, runs out of memory or
//! is killed takes nothing down with it, and the model is refused.
//!
//! The child is this executable started with [`PARSE_JAIL_ARG`] first, so a
//! binary that loads models calls [`enter_if_requested`] first thing in
//! `main`. Outside Linux there is no seccomp: the child runs with the
//! resource limits only, and the node logs that when it starts one. On
//! Windows the limits are a job object the child puts itself in before it
//! parses (a memory cap, a CPU-time cap, one process, no UI access), and the
//! external-data files are named to the child by path instead of handed over
//! as descriptors.
//!
//! This is not the runtime-host confinement of `praecise_host::sandbox`,
//! which needs unprivileged user namespaces and lets a whole engine run; the
//! parser needs no namespace because it may not open anything at all.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

/// First argument that turns this executable into the parser child.
pub const PARSE_JAIL_ARG: &str = "__tenzro-parse-jail";

/// Address space the parser child may map beyond what it has mapped when it
/// locks down (the executable and its libraries: a CUDA build of the node
/// maps more than this before it parses anything), in bytes. An ONNX child
/// may also map twice the size of the model and its external data, which it
/// holds in memory while ONNX Runtime reads it.
pub const MEMORY_CAP_BYTES: u64 = 1 << 30;

/// First descriptor of the external-data files handed to an ONNX child.
#[cfg(unix)]
const FIRST_SIDECAR_FD: i32 = 3;

/// Most external-data files handed to an ONNX child.
const MAX_SIDECARS: usize = 8;

/// CPU seconds the parser child may use.
pub const CPU_CAP_SECONDS: u64 = 60;

/// Exit status of a child that parsed the file and refused it.
const EXIT_REFUSED: i32 = 2;

/// Largest index the node reads back from a child.
const INDEX_CAP_BYTES: u64 = 64 << 20;

/// Longest diagnostic the node keeps from a child's standard error.
const STDERR_CAP_BYTES: u64 = 16 << 10;

/// The file formats parsed in the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    /// llama.cpp GGUF.
    Gguf,
    /// ONNX protobuf.
    Onnx,
}

impl ModelFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gguf => "gguf",
            Self::Onnx => "onnx",
        }
    }

    fn parse(s: &OsStr) -> Option<Self> {
        match s.to_str()? {
            "gguf" => Some(Self::Gguf),
            "onnx" => Some(Self::Onnx),
            _ => None,
        }
    }
}

/// One tensor of a GGUF file, as its header describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorEntry {
    /// Tensor name.
    pub name: String,
    /// ggml type id.
    pub ggml_type: u32,
    /// Offset of its data from the start of the data section.
    pub offset: u64,
    /// Size of its data in bytes.
    pub size: u64,
}

/// What the child found in a model file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelIndex {
    /// The format parsed.
    pub format: ModelFormat,
    /// Offset of the data section from the start of the file (GGUF; 0 for
    /// ONNX).
    pub data_offset: u64,
    /// Metadata entries (GGUF key/value pairs; ONNX top-level fields).
    pub entries: u64,
    /// The tensors (GGUF; empty for ONNX, whose tensors sit in its graph).
    pub tensors: Vec<TensorEntry>,
}

impl ModelIndex {
    /// Checks the index against the file it describes: the format asked for,
    /// and every tensor's data inside the file.
    fn check(&self, format: ModelFormat, file_len: u64) -> Result<(), String> {
        if self.format != format {
            return Err(format!("parsed as {:?}, asked for {format:?}", self.format));
        }
        if self.data_offset > file_len {
            return Err("data section starts past the end of the file".into());
        }
        let data_len = file_len - self.data_offset;
        for t in &self.tensors {
            let end = t.offset.checked_add(t.size);
            if end.is_none_or(|end| end > data_len) {
                return Err(format!("tensor {} lies outside the file", t.name));
            }
        }
        Ok(())
    }
}

/// Why a model file was refused.
#[derive(Debug)]
pub enum JailError {
    /// The file could not be opened or the child could not be started.
    Start(String),
    /// The child parsed the file and refused it.
    Refused(String),
    /// The child died: crashed, ran past a cap or was killed.
    Crashed {
        /// Exit status, when it exited.
        code: Option<i32>,
        /// Signal, when one killed it.
        signal: Option<i32>,
        /// The end of its standard error.
        stderr: String,
    },
    /// The child exited zero but its index is malformed or inconsistent
    /// with the file.
    BadIndex(String),
}

impl fmt::Display for JailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(e) => write!(f, "model parser could not start: {e}"),
            Self::Refused(e) => write!(f, "model file refused by its parser: {e}"),
            Self::Crashed {
                code,
                signal,
                stderr,
            } => write!(
                f,
                "model parser died (exit {code:?}, signal {signal:?}); the model is refused: {stderr}"
            ),
            Self::BadIndex(e) => write!(f, "model parser returned a bad index: {e}"),
        }
    }
}

impl std::error::Error for JailError {}

/// Parses the header of the model file at `path` in a locked-down child
/// process and returns its index. The model is refused unless the child
/// exits zero with an index consistent with the file.
///
/// # Errors
///
/// [`JailError`] for every refusal.
pub fn admit(path: &Path, format: ModelFormat) -> Result<ModelIndex, JailError> {
    let file =
        File::open(path).map_err(|e| JailError::Start(format!("{}: {e}", path.display())))?;
    let file_len = file
        .metadata()
        .map_err(|e| JailError::Start(format!("{}: {e}", path.display())))?
        .len();
    let exe = std::env::current_exe()
        .map_err(|e| JailError::Start(format!("locating the executable: {e}")))?;
    if !cfg!(target_os = "linux") {
        tracing::warn!(
            path = %path.display(),
            "model parser runs in its own process with resource caps only: seccomp needs Linux"
        );
    }
    let mut cmd = Command::new(exe);
    cmd.arg(PARSE_JAIL_ARG).arg(format.as_str());
    let sidecars = if format == ModelFormat::Onnx {
        sidecars(path)?
    } else {
        Vec::new()
    };
    #[cfg(windows)]
    for (name, file) in &sidecars {
        cmd.arg(format!("{name}={}", file.display()));
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        for (i, (name, _)) in sidecars.iter().enumerate() {
            cmd.arg(format!("{name}={}", FIRST_SIDECAR_FD + i as i32));
        }
        let fds: Vec<i32> = sidecars.iter().map(|(_, f)| f.as_raw_fd()).collect();
        // SAFETY: between fork and exec the closure only calls dup2, which
        // is async-signal-safe; each source descriptor stays open in the
        // parent until the child has been spawned.
        unsafe {
            cmd.pre_exec(move || {
                for (i, fd) in fds.iter().enumerate() {
                    if libc::dup2(*fd, FIRST_SIDECAR_FD + i as i32) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    cmd.env_clear();
    // The child is this executable started again: it keeps the loader path
    // this process was started with (a host that finds ONNX Runtime or the
    // CUDA libraries through it), and nothing else of the environment.
    if let Some(path) = std::env::var_os("LD_LIBRARY_PATH") {
        cmd.env("LD_LIBRARY_PATH", path);
    }
    // Windows finds its DLLs (ONNX Runtime, the CUDA runtime) through PATH and
    // needs SystemRoot to load anything at all.
    #[cfg(windows)]
    for key in ["PATH", "SystemRoot"] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    let mut child = cmd
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| JailError::Start(e.to_string()))?;
    drop(sidecars);

    let stderr = child.stderr.take().expect("piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.take(STDERR_CAP_BYTES).read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });
    let mut out = Vec::new();
    let stdout = child.stdout.take().expect("piped");
    let read = stdout.take(INDEX_CAP_BYTES + 1).read_to_end(&mut out);
    if out.len() as u64 > INDEX_CAP_BYTES {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|e| JailError::Start(e.to_string()))?;
    let stderr = stderr_reader.join().unwrap_or_default();

    if !status.success() {
        #[cfg(unix)]
        let signal = std::os::unix::process::ExitStatusExt::signal(&status);
        #[cfg(not(unix))]
        let signal = None;
        return Err(match status.code() {
            Some(EXIT_REFUSED) => JailError::Refused(stderr.trim().to_string()),
            code => JailError::Crashed {
                code,
                signal,
                stderr: stderr.trim().to_string(),
            },
        });
    }
    read.map_err(|e| JailError::BadIndex(e.to_string()))?;
    if out.len() as u64 > INDEX_CAP_BYTES {
        return Err(JailError::BadIndex("index larger than the cap".into()));
    }
    let index: ModelIndex =
        serde_json::from_slice(&out).map_err(|e| JailError::BadIndex(e.to_string()))?;
    index.check(format, file_len).map_err(JailError::BadIndex)?;
    Ok(index)
}

/// The external-data files beside an ONNX model, by the name the model
/// refers to them by: the conventional names only, and only regular files.
fn sidecar_candidates(model: &Path) -> Vec<(String, std::path::PathBuf)> {
    let (Some(dir), Some(name), Some(stem)) = (
        model.parent(),
        model.file_name().and_then(OsStr::to_str),
        model.file_stem().and_then(OsStr::to_str),
    ) else {
        return Vec::new();
    };
    let mut names = vec![
        format!("{name}.data"),
        format!("{name}_data"),
        format!("{stem}.onnx_data"),
        format!("{stem}.onnx.data"),
        format!("{stem}.data"),
    ];
    names.dedup();
    let mut out: Vec<(String, std::path::PathBuf)> = Vec::new();
    for n in names {
        let p = dir.join(&n);
        if out.iter().any(|(m, _)| *m == n) || !p.is_file() {
            continue;
        }
        out.push((n, p));
    }
    out.truncate(MAX_SIDECARS);
    out
}

/// The external-data files beside an ONNX model, opened read-only.
#[cfg(unix)]
fn sidecars(model: &Path) -> Result<Vec<(String, File)>, JailError> {
    sidecar_candidates(model)
        .into_iter()
        .map(|(n, p)| {
            File::open(&p)
                .map(|f| (n, f))
                .map_err(|e| JailError::Start(format!("{}: {e}", p.display())))
        })
        .collect()
}

/// The external-data files beside an ONNX model, by path: the child opens
/// them before it locks itself down.
#[cfg(not(unix))]
fn sidecars(model: &Path) -> Result<Vec<(String, std::path::PathBuf)>, JailError> {
    Ok(sidecar_candidates(model))
}

/// A parser the child runs on its standard input once locked down.
pub type Parser = fn(ModelFormat) -> Result<ModelIndex, String>;

/// When this process was started as the parser child, lock it down, parse
/// its standard input and exit; never returns in that case. Otherwise
/// returns immediately. Call first thing in `main`, before any thread is
/// started.
pub fn enter_if_requested() {
    enter_if_requested_with(parse);
}

/// [`enter_if_requested`] with the parser given.
pub fn enter_if_requested_with(parser: Parser) {
    let mut args = std::env::args_os();
    let _exe = args.next();
    if args.next().as_deref() != Some(OsStr::new(PARSE_JAIL_ARG)) {
        return;
    }
    let Some(format) = args.next().as_deref().and_then(ModelFormat::parse) else {
        eprintln!("model parser: no format given");
        exit_now(EXIT_REFUSED);
    };
    let mut cap = MEMORY_CAP_BYTES;
    if format == ModelFormat::Onnx {
        match onnx::prepare(args) {
            Ok(held) => cap = cap.saturating_add(held.saturating_mul(2)),
            Err(e) => {
                eprintln!("model parser: {e}");
                exit_now(EXIT_REFUSED);
            }
        }
    }
    if let Err(e) = lock_down_with(cap) {
        eprintln!("model parser: lock-down refused: {e}");
        exit_now(EXIT_REFUSED);
    }
    match parser(format) {
        Ok(index) => {
            let json = serde_json::to_vec(&index).expect("index encodes");
            let mut out = std::io::stdout().lock();
            if out.write_all(&json).and_then(|()| out.flush()).is_err() {
                exit_now(EXIT_REFUSED);
            }
            exit_now(0);
        }
        Err(e) => {
            eprintln!("{e}");
            exit_now(EXIT_REFUSED);
        }
    }
}

/// Address space this process has mapped, in bytes: the first field of
/// `/proc/self/statm`, in pages. Zero where there is no procfs, which leaves
/// the cap as the allowance alone.
fn mapped_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let pages = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<u64>().ok());
        // SAFETY: sysconf only reads a system constant.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if let (Some(pages), Ok(page)) = (pages, u64::try_from(page)) {
            return pages.saturating_mul(page);
        }
    }
    #[cfg(windows)]
    {
        return windows_jail::committed_bytes();
    }
    #[cfg(not(windows))]
    0
}

/// Exits without running exit handlers: they belong to the libraries
/// linked in, and may make calls the allow-list refuses.
fn exit_now(code: i32) -> ! {
    #[cfg(unix)]
    {
        // SAFETY: `_exit` only ends the process.
        unsafe { libc::_exit(code) }
    }
    #[cfg(windows)]
    {
        windows_jail::terminate(code)
    }
}

/// Applies the resource caps and, on Linux, `no_new_privs` and the seccomp
/// allow-list to the calling process. Irreversible.
///
/// # Errors
///
/// When the kernel refuses a step.
pub fn lock_down() -> Result<(), String> {
    lock_down_with(MEMORY_CAP_BYTES)
}

#[cfg(windows)]
fn lock_down_with(memory_cap: u64) -> Result<(), String> {
    windows_jail::lock_down(mapped_bytes().saturating_add(memory_cap), CPU_CAP_SECONDS)
}

#[cfg(unix)]
fn lock_down_with(memory_cap: u64) -> Result<(), String> {
    let memory_cap = mapped_bytes().saturating_add(memory_cap);
    for (resource, limit) in [
        (libc::RLIMIT_AS, memory_cap),
        (libc::RLIMIT_CPU, CPU_CAP_SECONDS),
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_FSIZE, 0),
    ] {
        let rl = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };
        // SAFETY: `rl` is a valid rlimit for the duration of the call.
        if unsafe { libc::setrlimit(resource, &rl) } != 0 {
            return Err(format!("setrlimit: {}", std::io::Error::last_os_error()));
        }
    }
    #[cfg(target_os = "linux")]
    seccomp::install()?;
    Ok(())
}

/// The Windows limits: a job object the parser child puts itself in.
#[cfg(windows)]
mod windows_jail {
    use std::os::windows::io::{FromRawHandle, RawHandle};

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOB_OBJECT_LIMIT_PROCESS_TIME, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

    /// Every UI restriction a job can carry (`JOB_OBJECT_UILIMIT_ALL`).
    const UILIMIT_ALL: u32 = 0xff;

    /// Bytes this process has committed.
    pub(super) fn committed_bytes() -> u64 {
        // SAFETY: the counters struct is plain data sized for the call.
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            let ok = GetProcessMemoryInfo(GetCurrentProcess(), (&raw mut c).cast(), c.cb);
            if ok == 0 { 0 } else { c.PrivateUsage as u64 }
        }
    }

    /// End the process now, without running exit handlers.
    pub(super) fn terminate(code: i32) -> ! {
        // SAFETY: ends this process only.
        unsafe { TerminateProcess(GetCurrentProcess(), code as u32) };
        std::process::abort()
    }

    /// The model file the node handed over as standard input.
    pub(super) fn stdin_file() -> Result<std::fs::File, String> {
        // SAFETY: the handle is this process's standard input, which the node
        // set to the model file; the caller keeps the file from closing it.
        let h: RawHandle = unsafe { GetStdHandle(STD_INPUT_HANDLE) } as RawHandle;
        if h.is_null() || h as isize == INVALID_HANDLE_VALUE as isize {
            return Err("standard input is not a readable file".into());
        }
        // SAFETY: as above.
        Ok(unsafe { std::fs::File::from_raw_handle(h) })
    }

    /// Put this process in a job object with the caps. Irreversible: the job
    /// outlives the handle and holds the process until it exits.
    pub(super) fn lock_down(memory_cap: u64, cpu_seconds: u64) -> Result<(), String> {
        // SAFETY: plain FFI over structs on the stack; the job handle is
        // closed after the process is in it (the job lives while it has a
        // process).
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(format!("CreateJobObjectW: error {}", GetLastError()));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_PROCESS_TIME
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            info.BasicLimitInformation.PerProcessUserTimeLimit =
                i64::try_from(cpu_seconds.saturating_mul(10_000_000)).unwrap_or(i64::MAX);
            info.BasicLimitInformation.ActiveProcessLimit = 1;
            info.ProcessMemoryLimit = usize::try_from(memory_cap).unwrap_or(usize::MAX);
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let e = GetLastError();
                CloseHandle(job);
                return Err(format!("SetInformationJobObject(limits): error {e}"));
            }
            let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: UILIMIT_ALL,
            };
            if SetInformationJobObject(
                job,
                JobObjectBasicUIRestrictions,
                (&raw const ui).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            ) == 0
            {
                let e = GetLastError();
                CloseHandle(job);
                return Err(format!("SetInformationJobObject(ui): error {e}"));
            }
            if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
                let e = GetLastError();
                CloseHandle(job);
                return Err(format!("AssignProcessToJobObject: error {e}"));
            }
            CloseHandle(job);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod seccomp {
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    const OFFSET_NR: u32 = 0;
    const OFFSET_ARCH: u32 = 4;

    /// The calls the parser may make. Anything else kills it.
    pub(super) const ALLOWED: &[libc::c_long] = &[
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_write,
        libc::SYS_lseek,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fcntl,
        libc::SYS_close,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_sched_yield,
        libc::SYS_clock_gettime,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        }
    }

    pub(super) fn install() -> Result<(), String> {
        let ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        let ret = (libc::BPF_RET | libc::BPF_K) as u16;
        let mut f = vec![
            stmt(ld, OFFSET_ARCH),
            jeq(AUDIT_ARCH, 1, 0),
            stmt(ret, SECCOMP_RET_KILL_PROCESS),
            stmt(ld, OFFSET_NR),
        ];
        for nr in ALLOWED {
            f.push(jeq(*nr as u32, 0, 1));
            f.push(stmt(ret, SECCOMP_RET_ALLOW));
        }
        f.push(stmt(ret, SECCOMP_RET_KILL_PROCESS));
        let prog = libc::sock_fprog {
            len: u16::try_from(f.len()).expect("filter fits"),
            filter: f.as_mut_ptr(),
        };
        // SAFETY: plain prctl calls; `prog` points at `f`, alive across them.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(format!("no_new_privs: {}", std::io::Error::last_os_error()));
            }
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            ) != 0
            {
                return Err(format!("seccomp: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

/// The parser the node's child runs: llama.cpp's own GGUF reader for GGUF,
/// ONNX Runtime's own reader for ONNX.
///
/// # Errors
///
/// The reason the file is refused.
pub fn parse(format: ModelFormat) -> Result<ModelIndex, String> {
    match format {
        ModelFormat::Gguf => parse_gguf(),
        ModelFormat::Onnx => parse_onnx(),
    }
}

fn parse_gguf() -> Result<ModelIndex, String> {
    use llama_cpp_sys_2 as sys;
    // SAFETY: fd 0 is the model file the node opened for this process; the
    // FILE takes it over and `gguf_init_from_file_ptr` only reads through it.
    // On Windows the C runtime sets up fd 0 from the inherited handle.
    let file = unsafe { libc::fdopen(0, c"rb".as_ptr()) };
    if file.is_null() {
        return Err("standard input is not a readable file".into());
    }
    let params = sys::gguf_init_params {
        no_alloc: true,
        ctx: std::ptr::null_mut(),
    };
    // SAFETY: `file` is a valid FILE for reading.
    let ctx = unsafe { sys::gguf_init_from_file_ptr(file.cast(), params) };
    if ctx.is_null() {
        return Err("llama.cpp refused the GGUF header".into());
    }
    // SAFETY: `ctx` is a valid context until `gguf_free`; every id is below
    // the count it reports, and names are NUL-terminated strings it owns.
    let index = unsafe {
        let n = sys::gguf_get_n_tensors(ctx);
        let mut tensors = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        for i in 0..n {
            let name = std::ffi::CStr::from_ptr(sys::gguf_get_tensor_name(ctx, i))
                .to_string_lossy()
                .into_owned();
            // The binding types the ggml type id as u32 or i32 depending on the
            // target (MSVC makes C enums signed); a negative id is a corrupt
            // header, and is refused with the tensor's name.
            let raw_type = sys::gguf_get_tensor_type(ctx, i);
            let Ok(ggml_type) = u32::try_from(i64::from(raw_type)) else {
                sys::gguf_free(ctx);
                return Err(format!(
                    "GGUF tensor {name} has an invalid ggml type id {raw_type}"
                ));
            };
            tensors.push(TensorEntry {
                name,
                ggml_type,
                offset: sys::gguf_get_tensor_offset(ctx, i) as u64,
                size: sys::gguf_get_tensor_size(ctx, i) as u64,
            });
        }
        let index = ModelIndex {
            format: ModelFormat::Gguf,
            data_offset: sys::gguf_get_data_offset(ctx) as u64,
            entries: u64::try_from(sys::gguf_get_n_kv(ctx)).unwrap_or(0),
            tensors,
        };
        sys::gguf_free(ctx);
        index
    };
    Ok(index)
}

/// Reads the model into memory and walks its top-level fields without
/// recursion (every field's wire type is valid and every length-delimited
/// field lies inside the file; `ir_version`, field 1, and `graph`, field 7,
/// are present), then has ONNX Runtime load it.
fn parse_onnx() -> Result<ModelIndex, String> {
    #[cfg(unix)]
    let mut file = {
        use std::os::fd::FromRawFd;
        // SAFETY: fd 0 is the model file the node opened for this process.
        std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(0) })
    };
    #[cfg(windows)]
    let mut file = std::mem::ManuallyDrop::new(windows_jail::stdin_file()?);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let entries = onnx::top_level_fields(&bytes)?;
    onnx::load(&bytes)?;
    Ok(ModelIndex {
        format: ModelFormat::Onnx,
        data_offset: 0,
        entries,
        tensors: Vec::new(),
    })
}

mod onnx {
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::Read;
    use std::sync::Arc;

    use praecise_onnx::parse::ParseCheck;

    thread_local! {
        /// The parse made ready before the lock-down, holding the external
        /// data in memory. The child runs one thread.
        static PREPARED: RefCell<Option<ParseCheck>> = const { RefCell::new(None) };
    }

    /// Starts ONNX Runtime and reads the external-data descriptors named in
    /// `args` (`<name>=<fd>`) into a parse with one thread and no graph
    /// optimisation. Returns the bytes held, model included.
    pub(super) fn prepare(args: impl Iterator<Item = OsString>) -> Result<u64, String> {
        let mut check = ParseCheck::new()?;
        #[cfg(unix)]
        // SAFETY: fstat on fd 0, the model file, into a zeroed stat.
        let mut held = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(0, &mut st) == 0 {
                st.st_size as u64
            } else {
                0
            }
        };
        #[cfg(windows)]
        let mut held = {
            let stdin = std::mem::ManuallyDrop::new(super::windows_jail::stdin_file()?);
            stdin.metadata().map_or(0, |m| m.len())
        };
        for arg in args.take(super::MAX_SIDECARS) {
            let arg = arg
                .into_string()
                .map_err(|_| "external-data argument is not UTF-8")?;
            #[cfg(unix)]
            let (name, mut f) = {
                use std::os::fd::FromRawFd;
                let (name, fd) = arg
                    .rsplit_once('=')
                    .and_then(|(n, fd)| Some((n.to_string(), fd.parse::<i32>().ok()?)))
                    .filter(|(_, fd)| *fd >= super::FIRST_SIDECAR_FD)
                    .ok_or("external-data argument is not <name>=<fd>")?;
                // SAFETY: the node handed this descriptor to this process for
                // this one file; nothing else owns it.
                (name, unsafe { File::from_raw_fd(fd) })
            };
            #[cfg(windows)]
            let (name, mut f) = {
                let (name, path) = arg
                    .split_once('=')
                    .ok_or("external-data argument is not <name>=<path>")?;
                let f = File::open(path).map_err(|e| format!("{name}: {e}"))?;
                (name.to_string(), f)
            };
            let len = f
                .metadata()
                .map_err(|e| format!("{name}: {e}"))
                .and_then(|m| usize::try_from(m.len()).map_err(|e| format!("{name}: {e}")))?;
            // One allocation, read in place: the data is held until the
            // model is parsed and the process exits.
            let mut data: Arc<[u8]> = std::iter::repeat_n(0u8, len).collect();
            f.read_exact(Arc::get_mut(&mut data).expect("the only handle"))
                .map_err(|e| format!("{name}: {e}"))?;
            held = held.saturating_add(len as u64);
            check = check.with_external_data(&name, data)?;
        }
        PREPARED.with(|p| *p.borrow_mut() = Some(check));
        Ok(held)
    }

    /// ONNX Runtime's verdict on the model: its protobuf reader over the
    /// whole `ModelProto`, then the graph checks a session load makes.
    pub(super) fn load(bytes: &[u8]) -> Result<(), String> {
        PREPARED
            .with(|p| p.borrow_mut().take())
            .ok_or("ONNX Runtime was not prepared before the lock-down")?
            .check(bytes)
    }

    fn varint(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *bytes.get(*pos).ok_or("truncated varint")?;
            *pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("varint longer than 10 bytes".into())
    }

    /// The number of top-level fields of a `ModelProto`, each checked to lie
    /// inside the file.
    pub(super) fn top_level_fields(bytes: &[u8]) -> Result<u64, String> {
        let (mut pos, mut ir_version, mut graph, mut entries) = (0usize, false, false, 0u64);
        while pos < bytes.len() {
            let key = varint(bytes, &mut pos)?;
            let (field, wire) = (key >> 3, key & 7);
            if field == 0 {
                return Err("field number 0".into());
            }
            let skip = match wire {
                0 => {
                    varint(bytes, &mut pos)?;
                    0
                }
                1 => 8,
                2 => varint(bytes, &mut pos)?,
                5 => 4,
                w => return Err(format!("wire type {w} at offset {pos}")),
            };
            pos = usize::try_from(skip)
                .ok()
                .and_then(|s| pos.checked_add(s))
                .filter(|e| *e <= bytes.len())
                .ok_or("field runs past the end of the file")?;
            ir_version |= field == 1 && wire == 0;
            graph |= field == 7 && wire == 2;
            entries += 1;
        }
        if !ir_version || !graph {
            return Err("not an ONNX model: ir_version or graph missing".into());
        }
        Ok(entries)
    }
}

/// Why a llama.cpp model did not load.
#[derive(Debug)]
pub enum LlamaLoadError {
    /// The file was refused before llama.cpp loaded it.
    Refused(JailError),
    /// llama.cpp failed to load an admitted file.
    Load(llama_cpp_2::LlamaModelLoadError),
}

impl fmt::Display for LlamaLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(e) => e.fmt(f),
            Self::Load(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LlamaLoadError {}

/// Loads a GGUF model with llama.cpp once its header has been parsed in the
/// parser child ([`admit`]). Every llama.cpp model load goes through here.
///
/// # Errors
///
/// [`LlamaLoadError::Refused`] when the parser child refuses the file,
/// [`LlamaLoadError::Load`] when llama.cpp then fails to load it.
pub fn load_llama(
    backend: &llama_cpp_2::llama_backend::LlamaBackend,
    path: impl AsRef<Path>,
    params: &llama_cpp_2::model::params::LlamaModelParams,
) -> Result<llama_cpp_2::model::LlamaModel, LlamaLoadError> {
    let path = path.as_ref();
    let index = admit(path, ModelFormat::Gguf).map_err(LlamaLoadError::Refused)?;
    tracing::debug!(
        path = %path.display(),
        tensors = index.tensors.len(),
        "GGUF header admitted by the parser child"
    );
    llama_cpp_2::model::LlamaModel::load_from_file(backend, path, params)
        .map_err(LlamaLoadError::Load)
}
