//! `enclave_probe create <label>` makes the label's device key; `enclave_probe sign <label>` opens it
//! and signs a fixed digest. Used by scripts/release/test_enclave_resign.sh to show a key made by a
//! binary signed with one identity opens after the binary is re-signed with another.
use tenzro_device_key::{create, open};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(cmd), Some(label)) = (args.next(), args.next()) else {
        eprintln!("usage: enclave_probe create|sign <label>");
        std::process::exit(2);
    };
    let result = match cmd.as_str() {
        "create" => create(&label).map(|k| k.public_key().is_ok()),
        "sign" => open(&label).and_then(|k| k.sign_prehash(&[7u8; 32]).map(|_| true)),
        other => {
            eprintln!("unknown command {other}");
            std::process::exit(2);
        }
    };
    match result {
        Ok(true) => println!("OK {cmd} {label}"),
        Ok(false) => {
            println!("FAIL {cmd} {label}: no public key");
            std::process::exit(1);
        }
        Err(e) => {
            println!("FAIL {cmd} {label}: {e}");
            std::process::exit(1);
        }
    }
}
