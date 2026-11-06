//! Bytes held in a store, by column family and key family.
//!
//! Opens each store read-only and sums key and value bytes (uncompressed)
//! per column family and per key family, so the growth of a run can be
//! attributed to the records that cause it. A key family is the key up to
//! its first non-printable byte, without its last `/` or `:` separated
//! segment; a key of hex digits only is reported as `<hexN>`; a key whose
//! first byte is a letter followed by binary is reported by that letter.
//!
//! Usage:
//!   cargo run --release --example key_census -- <db dir>...

use rocksdb::{DB, IteratorMode, Options};
use std::collections::BTreeMap;

fn family(key: &[u8]) -> String {
    let printable = key
        .iter()
        .position(|b| !(0x20..0x7f).contains(b))
        .unwrap_or(key.len());
    let text = String::from_utf8_lossy(&key[..printable]).to_string();
    if printable < key.len() && printable <= 1 {
        return format!("{}<bin>", text);
    }
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit()) && printable == key.len() {
        return format!("<hex{}>", text.len());
    }
    match text.rfind(['/', ':']) {
        Some(i) if printable == key.len() => text[..=i].to_string(),
        _ if printable < key.len() => format!("{text}<bin>"),
        _ => text.chars().take(24).collect(),
    }
}

fn main() {
    let dirs: Vec<String> = std::env::args().skip(1).collect();
    if dirs.is_empty() {
        eprintln!("usage: key_census <db dir>...");
        std::process::exit(2);
    }
    for dir in dirs {
        let cfs = DB::list_cf(&Options::default(), &dir).unwrap_or_default();
        let db = DB::open_cf_for_read_only(&Options::default(), &dir, &cfs, false)
            .unwrap_or_else(|e| panic!("open {dir}: {e}"));
        println!("store {dir}");
        for cf in &cfs {
            let handle = db.cf_handle(cf).expect("listed column family");
            let mut by: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
            for item in db.iterator_cf(handle, IteratorMode::Start) {
                let (k, v) = item.expect("iterate");
                let e = by.entry(family(&k)).or_default();
                e.0 += 1;
                e.1 += k.len() as u64;
                e.2 += v.len() as u64;
            }
            let total: u64 = by.values().map(|e| e.1 + e.2).sum();
            if total == 0 {
                continue;
            }
            let sst = db
                .property_int_value_cf(handle, "rocksdb.total-sst-files-size")
                .ok()
                .flatten()
                .unwrap_or(0);
            println!("cf {cf} raw_bytes {total} sst_bytes {sst}");
            let mut rows: Vec<_> = by.into_iter().collect();
            rows.sort_by_key(|r| std::cmp::Reverse(r.1.1 + r.1.2));
            for (fam, (n, kb, vb)) in rows.into_iter().take(25) {
                println!("  {cf}\t{fam}\tcount {n}\tkey_bytes {kb}\tvalue_bytes {vb}");
            }
        }
    }
}
