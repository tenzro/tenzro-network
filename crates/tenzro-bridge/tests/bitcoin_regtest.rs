//! The deposit descriptor and a withdrawal, checked by Bitcoin Core.
//!
//! A regtest node parses the descriptor (its checksum included), derives its
//! address, holds a deposit to it, and accepts the withdrawal this crate
//! plans and assembles from two of three signatures; it rejects the same
//! withdrawal with one. Needs Bitcoin Core's `bitcoind` and `bitcoin-cli`,
//! so it is ignored by default:
//!
//! ```text
//! BITCOIN_BIN=/path/to/bitcoin/bin cargo test -p tenzro-bridge --test bitcoin_regtest -- --ignored
//! ```

use std::path::PathBuf;
use std::process::{Child, Command};

use serde_json::Value;
use tenzro_bridge::route::bitcoin::sha256d;
use tenzro_bridge::route::bitcoin_spend::{DepositDescriptor, Utxo, plan_withdrawal};

struct Node {
    bin: PathBuf,
    dir: tempfile::TempDir,
    child: Child,
}

impl Node {
    fn start() -> Self {
        let bin = PathBuf::from(
            std::env::var("BITCOIN_BIN").expect("BITCOIN_BIN names Bitcoin Core's bin directory"),
        );
        let dir = tempfile::tempdir().unwrap();
        let port = 20_000 + (std::process::id() % 20_000) as u16;
        let child = Command::new(bin.join("bitcoind"))
            .arg("-regtest")
            .arg(format!("-datadir={}", dir.path().display()))
            .arg(format!("-rpcport={port}"))
            .arg(format!("-port={}", port + 1))
            .arg("-listen=0")
            .arg("-fallbackfee=0.0002")
            .arg("-txindex=0")
            .spawn()
            .unwrap();
        let node = Self { bin, dir, child };
        for _ in 0..200 {
            if node.try_cli(&["getblockchaininfo"]).is_some() {
                return node;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("bitcoind did not start");
    }

    fn port(&self) -> u16 {
        20_000 + (std::process::id() % 20_000) as u16
    }

    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let out = Command::new(self.bin.join("bitcoin-cli"))
            .arg("-regtest")
            .arg(format!("-datadir={}", self.dir.path().display()))
            .arg(format!("-rpcport={}", self.port()))
            .args(args)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8(out.stdout).unwrap().trim().to_string())
    }

    fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args)
            .unwrap_or_else(|| panic!("bitcoin-cli {args:?} failed"))
    }

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.cli(args)).unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.try_cli(&["stop"]);
        let _ = self.child.wait();
    }
}

fn signer(seed: u8) -> k256::schnorr::SigningKey {
    k256::schnorr::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}

#[test]
#[ignore]
fn bitcoin_core_accepts_a_withdrawal_signed_by_the_threshold() {
    let node = Node::start();
    let desc = DepositDescriptor {
        signers: (1..=3u8)
            .map(|i| <[u8; 32]>::from(signer(i).verifying_key().to_bytes()))
            .collect(),
        threshold: 2,
    };

    // Bitcoin Core reads the descriptor, checksum included, and derives the
    // same output script.
    let info = node.json(&["getdescriptorinfo", &desc.descriptor()]);
    assert_eq!(
        format!(
            "{}#{}",
            info["descriptor"]
                .as_str()
                .unwrap()
                .split('#')
                .next()
                .unwrap(),
            info["checksum"].as_str().unwrap()
        ),
        desc.descriptor()
    );
    let address = node.json(&["deriveaddresses", &desc.descriptor()])[0]
        .as_str()
        .unwrap()
        .to_string();
    let addr_info = node.json(&["validateaddress", &address]);
    assert_eq!(
        addr_info["scriptPubKey"].as_str().unwrap(),
        hex::encode(desc.script_pubkey().unwrap())
    );

    // Fund a wallet and deposit to the descriptor.
    node.cli(&["createwallet", "w"]);
    let mine_to = node.cli(&["getnewaddress"]);
    node.cli(&["generatetoaddress", "101", &mine_to]);
    let deposit_txid = node.cli(&["sendtoaddress", &address, "0.5"]);
    let block = node.json(&["generatetoaddress", "1", &mine_to])[0]
        .as_str()
        .unwrap()
        .to_string();
    let tx = node.json(&["getrawtransaction", &deposit_txid, "true", &block]);
    let vout = tx["vout"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["scriptPubKey"]["address"].as_str() == Some(address.as_str()))
        .unwrap();
    let mut txid: [u8; 32] = hex::decode(&deposit_txid).unwrap().try_into().unwrap();
    txid.reverse();
    let utxo = Utxo {
        txid,
        vout: vout["n"].as_u64().unwrap() as u32,
        value: 50_000_000,
    };

    // Withdraw part of it to a fresh wallet address, change back to the
    // descriptor.
    let payee = node.cli(&["getnewaddress", "", "bech32"]);
    let payee_script = hex::decode(
        node.json(&["validateaddress", &payee])["scriptPubKey"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let (w, rest) = plan_withdrawal(&desc, &[utxo], &payee_script, 20_000_000, 3).unwrap();
    assert_eq!(rest[0].value, 30_000_000);

    let sign = |seeds: &[u8]| -> Vec<Vec<([u8; 32], [u8; 64])>> {
        let digest = w.sighash(&desc, 0).unwrap();
        vec![
            seeds
                .iter()
                .map(|s| {
                    (
                        desc.signers[*s as usize - 1],
                        signer(*s).sign_raw(&digest, &[0; 32]).unwrap().to_bytes(),
                    )
                })
                .collect(),
        ]
    };
    let signed = hex::encode(w.assemble(&desc, &sign(&[1, 3])).unwrap());

    // The txid Tenzro tracked the change under is the one Bitcoin computes.
    let decoded = node.json(&["decoderawtransaction", &signed]);
    let mut planned = sha256d(&w.tx.encode());
    planned.reverse();
    assert_eq!(decoded["txid"].as_str().unwrap(), hex::encode(planned));

    let accept = node.json(&["testmempoolaccept", &format!("[\"{signed}\"]")]);
    assert_eq!(accept[0]["allowed"], true, "{accept}");
    let vsize = accept[0]["vsize"].as_u64().unwrap();
    let fee = 20_000_000 - w.tx.outputs[0].value;
    assert!(fee >= vsize * 3, "fee {fee} for {vsize} vbytes");

    // With one signature the script fails.
    let digest = w.sighash(&desc, 0).unwrap();
    let mut witness = vec![Vec::new(); 3];
    witness[2] = signer(1)
        .sign_raw(&digest, &[0; 32])
        .unwrap()
        .to_bytes()
        .to_vec();
    let mut short = Vec::new();
    let base = w.tx.encode();
    short.extend_from_slice(&base[..4]);
    short.extend_from_slice(&[0, 1]);
    short.extend_from_slice(&base[4..base.len() - 4]);
    short.push(5);
    for item in &witness {
        short.push(item.len() as u8);
        short.extend_from_slice(item);
    }
    let script = desc.leaf_script();
    short.push(script.len() as u8);
    short.extend_from_slice(&script);
    let control = desc.control_block().unwrap();
    short.push(control.len() as u8);
    short.extend_from_slice(&control);
    short.extend_from_slice(&base[base.len() - 4..]);
    let rejected = node.json(&[
        "testmempoolaccept",
        &format!("[\"{}\"]", hex::encode(short)),
    ]);
    assert_eq!(rejected[0]["allowed"], false, "{rejected}");

    node.cli(&["sendrawtransaction", &signed]);
    node.cli(&["generatetoaddress", "1", &mine_to]);
    let paid = node.json(&["getreceivedbyaddress", &payee, "1"]);
    assert_eq!(
        (paid.as_f64().unwrap() * 1e8).round() as u64,
        w.tx.outputs[0].value
    );
}
