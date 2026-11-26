//! `tenzro-receipt-verify [--model-hash HEX] [--nonce N] [--output TEXT] [FILE]`
//! `tenzro-receipt-verify --interaction [--expect HEX] [FILE]`
//! `tenzro-receipt-verify --run-manifest [--expect HEX] [FILE]`
//!
//! Reads a receipt (or a chat completion response carrying one as
//! `tenzro_receipt`) from FILE or standard input, verifies it, and prints
//! its digest. With `--interaction` it reads an interaction record instead
//! and prints its digest, checking it against `--expect` when given; with
//! `--run-manifest` it does the same for a harness run manifest. Exits 1
//! when it does not verify, 2 on bad usage.

use std::io::Read;

fn usage() -> ! {
    eprintln!("usage: tenzro-receipt-verify [--model-hash HEX] [--nonce N] [--output TEXT] [FILE]");
    eprintln!("       tenzro-receipt-verify --interaction [--expect HEX] [FILE]");
    eprintln!("       tenzro-receipt-verify --run-manifest [--expect HEX] [FILE]");
    std::process::exit(2)
}

fn main() {
    let mut model_hash = None;
    let mut nonce = None;
    let mut output = None;
    let mut path = None;
    let mut interaction = false;
    let mut run_manifest = false;
    let mut expect_digest = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--model-hash" => model_hash = Some(args.next().unwrap_or_else(|| usage())),
            "--nonce" => nonce = Some(args.next().unwrap_or_else(|| usage())),
            "--output" => output = Some(args.next().unwrap_or_else(|| usage())),
            "--interaction" => interaction = true,
            "--run-manifest" => run_manifest = true,
            "--expect" => expect_digest = Some(args.next().unwrap_or_else(|| usage())),
            _ if a.starts_with("--") => usage(),
            _ => path = Some(a),
        }
    }
    let mut raw = String::new();
    let read = match &path {
        Some(p) if p != "-" => std::fs::read_to_string(p).map(|s| raw = s),
        _ => std::io::stdin().read_to_string(&mut raw).map(|_| ()),
    };
    if let Err(e) = read {
        eprintln!("cannot read the receipt: {e}");
        std::process::exit(2);
    }
    if run_manifest {
        if interaction {
            usage();
        }
        print_digest(
            tenzro_receipt_verify::run_manifest::run_manifest_digest(&raw),
            expect_digest.as_deref(),
        );
    }
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("not JSON: {e}");
            std::process::exit(2);
        }
    };
    if interaction {
        print_digest(
            tenzro_receipt_verify::interaction::interaction_digest(&value),
            expect_digest.as_deref(),
        );
    }
    if expect_digest.is_some() {
        usage();
    }
    let receipt = value.get("tenzro_receipt").unwrap_or(&value);
    let output_hash = output
        .as_deref()
        .map(|t| tenzro_receipt_verify::output_hash(t, "", ""));
    let expect = tenzro_receipt_verify::Expect {
        model_hash: model_hash.as_deref(),
        nonce: nonce.as_deref(),
        output_hash: output_hash.as_deref(),
    };
    match tenzro_receipt_verify::verify(receipt, &expect)
        .and_then(|()| tenzro_receipt_verify::digest(receipt))
    {
        Ok(digest) => println!("verified {digest}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Prints a digest and exits: 0 when there is one (and it is `expect`, when
/// given), 1 otherwise.
fn print_digest<E: std::fmt::Display>(digest: Result<String, E>, expect: Option<&str>) -> ! {
    match digest {
        Ok(digest) => {
            let expect = expect.map(|e| e.trim().trim_start_matches("0x").to_ascii_lowercase());
            match expect {
                Some(e) if e != digest => {
                    eprintln!("the digest is {digest}, not the expected {e}");
                    std::process::exit(1);
                }
                _ => {
                    println!("digest {digest}");
                    std::process::exit(0);
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
