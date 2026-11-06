//! `tenzro-receipt-verify [--model-hash HEX] [--nonce N] [--output TEXT] [FILE]`
//!
//! Reads a receipt (or a chat completion response carrying one as
//! `tenzro_receipt`) from FILE or standard input, verifies it, and prints
//! its digest. Exits 1 when it does not verify, 2 on bad usage.

use std::io::Read;

fn usage() -> ! {
    eprintln!("usage: tenzro-receipt-verify [--model-hash HEX] [--nonce N] [--output TEXT] [FILE]");
    std::process::exit(2)
}

fn main() {
    let mut model_hash = None;
    let mut nonce = None;
    let mut output = None;
    let mut path = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--model-hash" => model_hash = Some(args.next().unwrap_or_else(|| usage())),
            "--nonce" => nonce = Some(args.next().unwrap_or_else(|| usage())),
            "--output" => output = Some(args.next().unwrap_or_else(|| usage())),
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
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("not JSON: {e}");
            std::process::exit(2);
        }
    };
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
