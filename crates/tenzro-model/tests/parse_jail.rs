//! The model parser child: a well-formed GGUF and ONNX file are admitted
//! with a correct index; malformed ones are refused by the parser; a planted
//! parser bug (an unchecked length, a wild write) kills only the child and
//! the model is refused while this process carries on; the seccomp
//! allow-list kills a child that opens a socket or a file. The child keeps
//! the loader path it was started with, and its memory cap is counted from
//! what it has mapped when it locks down, so a child as large as a CUDA build
//! of the node still parses a well-formed model.
//!
//! The child is this test executable, so `main` hands control to the parser
//! first, as the node's `main` does. Its parser is the node's, except for
//! files that start with `PLNT`, which reach a deliberately broken parser.

use std::io::Write;
use std::path::{Path, PathBuf};

use tenzro_model::parse_jail::{self, JailError, ModelFormat, ModelIndex};

const PLANTED_MAGIC: &[u8; 4] = b"PLNT";

/// The variable a host finds its shared libraries through, and what separates
/// the directories in it.
#[cfg(unix)]
const LOADER_VAR: (&str, &str) = ("LD_LIBRARY_PATH", ":");
#[cfg(windows)]
const LOADER_VAR: (&str, &str) = ("PATH", ";");

/// The first 16 bytes of the model on standard input, without moving the
/// file offset the real parser starts from.
fn peek_head(head: &mut [u8; 16]) -> usize {
    #[cfg(unix)]
    {
        // SAFETY: reads into `head` at offset 0 of fd 0 without moving the
        // file offset the real parser starts from.
        let n = unsafe { libc::pread(0, head.as_mut_ptr().cast(), head.len(), 0) };
        usize::try_from(n).unwrap_or(0)
    }
    #[cfg(windows)]
    {
        use std::io::{Seek, SeekFrom};
        use std::os::windows::fs::FileExt;
        use std::os::windows::io::AsHandle;
        let Ok(owned) = std::io::stdin().as_handle().try_clone_to_owned() else {
            return 0;
        };
        let mut f = std::fs::File::from(owned);
        let n = f.seek_read(head, 0).unwrap_or(0);
        let _ = f.seek(SeekFrom::Start(0));
        n
    }
}

/// The node's parser, except that a file starting with `PLNT` goes to a
/// parser with two planted bugs: byte 4 picks the bug, bytes 8..16 are the
/// length it trusts.
fn parser_with_planted_bugs(format: ModelFormat) -> Result<ModelIndex, String> {
    let mut head = [0u8; 16];
    let n = peek_head(&mut head);
    if n != 16 || &head[..4] != PLANTED_MAGIC {
        return parse_jail::parse(format);
    }
    let claimed = u64::from_le_bytes(head[8..16].try_into().unwrap());
    match head[4] {
        // Reports the loader path the child was started with.
        b'L' => Err(format!(
            "loader path: {}",
            std::env::var(LOADER_VAR.0).unwrap_or_else(|_| "none".into())
        )),
        // Trusts the length the file claims and allocates it.
        b'A' => {
            let buf = vec![1u8; claimed as usize];
            Err(format!("unreachable: allocated {}", buf.len()))
        }
        // Writes through a pointer the file supplies.
        _ => {
            // SAFETY: none; this is the planted memory-safety bug.
            unsafe { (claimed as usize as *mut u8).write_volatile(0x41) };
            Err("unreachable: wrote through a wild pointer".into())
        }
    }
}

fn gguf_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// A GGUF v3 file: one string key, one F32 tensor of four elements.
fn valid_gguf() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(b"GGUF");
    f.extend_from_slice(&3u32.to_le_bytes());
    f.extend_from_slice(&1i64.to_le_bytes()); // tensors
    f.extend_from_slice(&1i64.to_le_bytes()); // key/value pairs
    gguf_string(&mut f, "general.architecture");
    f.extend_from_slice(&8u32.to_le_bytes()); // string
    gguf_string(&mut f, "llama");
    gguf_string(&mut f, "w");
    f.extend_from_slice(&1u32.to_le_bytes()); // dims
    f.extend_from_slice(&4i64.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes()); // F32
    f.extend_from_slice(&0u64.to_le_bytes()); // offset
    while f.len() % 32 != 0 {
        f.push(0);
    }
    f.extend_from_slice(&[0u8; 16]);
    f
}

/// A GGUF v3 file with a tokenizer-sized vocabulary (`tokenizer.ggml.tokens`,
/// as many strings as a 150k-token model has) and one F32 tensor; reading it
/// allocates several MiB, as a real language model's header does.
fn large_vocab_gguf() -> Vec<u8> {
    const TOKENS: u64 = 150_000;
    let mut f = Vec::new();
    f.extend_from_slice(b"GGUF");
    f.extend_from_slice(&3u32.to_le_bytes());
    f.extend_from_slice(&1i64.to_le_bytes()); // tensors
    f.extend_from_slice(&2i64.to_le_bytes()); // key/value pairs
    gguf_string(&mut f, "general.architecture");
    f.extend_from_slice(&8u32.to_le_bytes()); // string
    gguf_string(&mut f, "llama");
    gguf_string(&mut f, "tokenizer.ggml.tokens");
    f.extend_from_slice(&9u32.to_le_bytes()); // array
    f.extend_from_slice(&8u32.to_le_bytes()); // of strings
    f.extend_from_slice(&TOKENS.to_le_bytes());
    for i in 0..TOKENS {
        gguf_string(&mut f, &format!("token-{i}"));
    }
    gguf_string(&mut f, "w");
    f.extend_from_slice(&1u32.to_le_bytes()); // dimensions
    f.extend_from_slice(&4u64.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes()); // F32
    f.extend_from_slice(&0u64.to_le_bytes()); // offset
    while f.len() % 32 != 0 {
        f.push(0);
    }
    f.extend_from_slice(&[0u8; 16]);
    f
}

fn pb_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A varint field.
fn pb_int(field: u64, v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    pb_varint(field << 3, &mut out);
    pb_varint(v, &mut out);
    out
}

/// A length-delimited field.
fn pb_bytes(field: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    pb_varint((field << 3) | 2, &mut out);
    pb_varint(bytes.len() as u64, &mut out);
    out.extend_from_slice(bytes);
    out
}

/// A float tensor value of shape `[1]` named `name` (`ValueInfoProto`).
fn float1(name: &str) -> Vec<u8> {
    let dim = pb_int(1, 1);
    let shape = pb_bytes(1, &dim);
    let tensor = [pb_int(1, 1), pb_bytes(2, &shape)].concat();
    [
        pb_bytes(1, name.as_bytes()),
        pb_bytes(2, &pb_bytes(1, &tensor)),
    ]
    .concat()
}

/// A `ModelProto` (ir_version 8, opset 13) whose graph has one node,
/// `op(input) -> y`, the graph inputs `inputs`, the output `y` and the
/// initializers `init`.
fn onnx_model(op: &str, input: &str, inputs: &[&str], init: &[Vec<u8>]) -> Vec<u8> {
    let node = [
        pb_bytes(1, input.as_bytes()),
        pb_bytes(2, b"y"),
        pb_bytes(4, op.as_bytes()),
    ]
    .concat();
    let mut graph = [pb_bytes(1, &node), pb_bytes(2, b"g")].concat();
    for t in init {
        graph.extend(pb_bytes(5, t));
    }
    for i in inputs {
        graph.extend(pb_bytes(11, &float1(i)));
    }
    graph.extend(pb_bytes(12, &float1("y")));
    [
        pb_int(1, 8),
        pb_bytes(7, &graph),
        pb_bytes(8, &pb_int(2, 13)),
    ]
    .concat()
}

/// A well-formed ONNX model: `Identity(x) -> y`.
fn valid_onnx() -> Vec<u8> {
    onnx_model("Identity", "x", &["x"], &[])
}

/// A float initializer `w` of shape `[1]` whose data is in the external file
/// `location` (`TensorProto` with `data_location = EXTERNAL`).
fn external_w(location: &str) -> Vec<u8> {
    let entry = [pb_bytes(1, b"location"), pb_bytes(2, location.as_bytes())].concat();
    [
        pb_int(1, 1),
        pb_int(2, 1),
        pb_bytes(8, b"w"),
        pb_bytes(13, &entry),
        pb_int(14, 1),
    ]
    .concat()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
    p
}

fn planted(kind: u8, claimed: u64) -> Vec<u8> {
    let mut f = PLANTED_MAGIC.to_vec();
    f.extend_from_slice(&[kind, 0, 0, 0]);
    f.extend_from_slice(&claimed.to_le_bytes());
    f
}

fn check(name: &str, ok: bool, detail: impl std::fmt::Debug) -> bool {
    println!(
        "{} {name}{}",
        if ok { "ok  " } else { "FAIL" },
        if ok {
            String::new()
        } else {
            format!(": {detail:?}")
        }
    );
    ok
}

/// Forks a child that locks itself down and makes one forbidden call; true
/// when the kernel kills it with SIGSYS.
#[cfg(target_os = "linux")]
fn forbidden_call_is_killed(call: fn()) -> (bool, i32) {
    // SAFETY: the child only locks down, makes the call and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        if parse_jail::lock_down().is_err() {
            unsafe { libc::_exit(3) };
        }
        call();
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    // SAFETY: waits for the child just forked.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    (
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
        status,
    )
}

/// Address space a CUDA build of the node has mapped (its GPU and ONNX
/// Runtime libraries) before its parser child locks down; more than the
/// child's whole memory allowance.
const CUDA_BUILD_MAPPED_BYTES: usize = 3 << 29;

/// Maps, without committing, as much address space as a CUDA build of the
/// node holds, so the child under test is as large as that executable.
#[cfg(windows)]
fn map_like_a_cuda_build() {
    // The job object caps committed memory, which a reservation does not
    // count, so there is nothing to reserve.
}

#[cfg(unix)]
fn map_like_a_cuda_build() {
    // SAFETY: an anonymous PROT_NONE reservation that is never touched.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            CUDA_BUILD_MAPPED_BYTES,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED, "reserve address space");
}

fn main() {
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(parse_jail::PARSE_JAIL_ARG))
    {
        map_like_a_cuda_build();
    }
    parse_jail::enter_if_requested_with(parser_with_planted_bugs);
    let dir = std::env::temp_dir().join(format!("tenzro-parse-jail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut all = true;

    #[cfg(target_os = "linux")]
    {
        let (killed, st) = forbidden_call_is_killed(|| unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        });
        all &= check("allow-list: a socket kills the parser", killed, st);
        let (killed, st) = forbidden_call_is_killed(|| unsafe {
            libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY);
        });
        all &= check("allow-list: opening a file kills the parser", killed, st);
        let (killed, st) = forbidden_call_is_killed(|| unsafe {
            libc::fork();
        });
        all &= check("allow-list: fork kills the parser", killed, st);
    }

    let gguf = write(&dir, "ok.gguf", &valid_gguf());
    let r = parse_jail::admit(&gguf, ModelFormat::Gguf);
    all &= check(
        "a well-formed GGUF is admitted with its tensor index",
        matches!(&r, Ok(i) if i.tensors.len() == 1 && i.tensors[0].name == "w" && i.tensors[0].size == 16 && i.entries == 1),
        &r,
    );

    // The child is this executable started again: it needs the loader path
    // this process was started with (a node that finds ONNX Runtime or the
    // CUDA libraries through it), and nothing else of its environment.
    let loader = std::env::var_os(LOADER_VAR.0);
    let mut marked = loader.clone().unwrap_or_default();
    if !marked.is_empty() {
        marked.push(LOADER_VAR.1);
    }
    marked.push("/opt/tenzro-loader-path-check");
    // SAFETY: no other thread of this process reads the environment.
    unsafe { std::env::set_var(LOADER_VAR.0, &marked) };
    let p = write(&dir, "loader.gguf", &planted(b'L', 0));
    let r = parse_jail::admit(&p, ModelFormat::Gguf);
    all &= check(
        "the parser child keeps the loader path it needs to start",
        matches!(&r, Err(JailError::Refused(m)) if m.contains("/opt/tenzro-loader-path-check")),
        &r,
    );
    // SAFETY: as above.
    match loader {
        Some(v) => unsafe { std::env::set_var(LOADER_VAR.0, v) },
        None => unsafe { std::env::remove_var(LOADER_VAR.0) },
    }

    let p = write(&dir, "large-vocab.gguf", &large_vocab_gguf());
    let r = parse_jail::admit(&p, ModelFormat::Gguf);
    all &= check(
        "a GGUF with a tokenizer-sized vocabulary is admitted by a child as large as a CUDA build",
        matches!(&r, Ok(i) if i.tensors.len() == 1 && i.entries == 2),
        &r,
    );

    let mut truncated = valid_gguf();
    truncated.truncate(40);
    let p = write(&dir, "truncated.gguf", &truncated);
    let r = parse_jail::admit(&p, ModelFormat::Gguf);
    all &= check(
        "a truncated GGUF is refused by llama.cpp's parser",
        matches!(r, Err(JailError::Refused(_))),
        &r,
    );

    let mut huge_key = b"GGUF".to_vec();
    huge_key.extend_from_slice(&3u32.to_le_bytes());
    huge_key.extend_from_slice(&0i64.to_le_bytes());
    huge_key.extend_from_slice(&1i64.to_le_bytes());
    huge_key.extend_from_slice(&u64::MAX.to_le_bytes());
    let p = write(&dir, "overlong-key.gguf", &huge_key);
    let r = parse_jail::admit(&p, ModelFormat::Gguf);
    all &= check(
        "a GGUF with an overflowing key length is refused",
        r.is_err(),
        &r,
    );

    let p = write(&dir, "oom.gguf", &planted(b'A', 8 << 30));
    let r = parse_jail::admit(&p, ModelFormat::Gguf);
    all &= check(
        "a planted unchecked length dies on the memory cap in the child only",
        matches!(r, Err(JailError::Crashed { .. })),
        &r,
    );

    let p = write(&dir, "wild.gguf", &planted(b'W', 0x10));
    let r = parse_jail::admit(&p, ModelFormat::Gguf);
    all &= check(
        "a planted wild write crashes the child only",
        // A signal on Unix, an exception status on Windows.
        match &r {
            Err(JailError::Crashed { signal, code, .. }) => {
                if cfg!(unix) {
                    signal.is_some()
                } else {
                    code.is_some_and(|c| c != 0)
                }
            }
            _ => false,
        },
        &r,
    );

    let r = parse_jail::admit(&gguf, ModelFormat::Gguf);
    all &= check(
        "this process carries on and still admits a good model",
        r.is_ok(),
        &r,
    );

    let p = write(&dir, "ok.onnx", &valid_onnx());
    let r = parse_jail::admit(&p, ModelFormat::Onnx);
    all &= check(
        "a well-formed ONNX model is admitted by ONNX Runtime in the child",
        matches!(&r, Ok(i) if i.entries == 3),
        &r,
    );

    // Top-level fields that lie inside the file, around a graph whose
    // first field runs past the graph's own end.
    let p = write(
        &dir,
        "bad-graph.onnx",
        &[
            pb_int(1, 8),
            pb_bytes(7, &[0x0a, 0x7f]),
            pb_bytes(8, &pb_int(2, 13)),
        ]
        .concat(),
    );
    let r = parse_jail::admit(&p, ModelFormat::Onnx);
    all &= check(
        "an ONNX graph that does not decode is refused by ONNX Runtime's reader",
        matches!(r, Err(JailError::Refused(_))),
        &r,
    );

    let p = write(
        &dir,
        "bad-op.onnx",
        &onnx_model("NoSuchOperator", "x", &["x"], &[]),
    );
    let r = parse_jail::admit(&p, ModelFormat::Onnx);
    all &= check(
        "an ONNX graph naming an operator that does not exist is refused",
        matches!(r, Err(JailError::Refused(_))),
        &r,
    );

    // External data: the model's initializer `w` lives in `ext.onnx.data`
    // beside it, which the child may not open itself.
    let ext = onnx_model("Identity", "w", &[], &[external_w("ext.onnx.data")]);
    let p = write(&dir, "ext.onnx", &ext);
    let r = parse_jail::admit(&p, ModelFormat::Onnx);
    all &= check(
        "an ONNX model whose external data is missing is refused",
        r.is_err(),
        &r,
    );
    write(&dir, "ext.onnx.data", &1.0f32.to_le_bytes());
    let r = parse_jail::admit(&p, ModelFormat::Onnx);
    all &= check(
        "an ONNX model is admitted with the external data beside it handed over",
        r.is_ok(),
        &r,
    );

    let p = write(&dir, "overrun.onnx", &[0x08, 0x09, 0x3a, 0xff, 0xff, 0x03]);
    let r = parse_jail::admit(&p, ModelFormat::Onnx);
    all &= check(
        "an ONNX field running past the file is refused",
        matches!(r, Err(JailError::Refused(_))),
        &r,
    );

    let r = parse_jail::admit(&gguf, ModelFormat::Onnx);
    all &= check("a GGUF passed as ONNX is refused", r.is_err(), &r);

    let _ = std::fs::remove_dir_all(&dir);
    if !all {
        std::process::exit(1);
    }
    println!("parse_jail: all cases passed");
}
