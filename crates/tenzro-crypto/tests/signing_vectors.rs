//! The shared signing vectors (`sdk/fixtures/signing`): the message
//! representative and P-256 digest of each signature context a small client
//! signs under, the bytes of an escrow voucher, the digest of a sensor
//! reading, the evidence item that carries a signed reading, the hash of a
//! native transaction and the request that submits a signed transfer.
//! Clients written outside
//! this workspace build the same bytes and are tested against this file.
//!
//! Rerun with `TENZRO_WRITE_FIXTURES=1` after a deliberate format change.

use tenzro_crypto::composite::{SignatureContext, message_representative, signing_digest};
use tenzro_crypto::{ClassicalProof, CompositeSignature};
use tenzro_types::evidence::{Evidence, sensor_reading_digest};
use tenzro_types::payment_authorization::escrow_voucher_preimage;
use tenzro_types::primitives::{Address, ChainId, Nonce, Timestamp};
use tenzro_types::transaction::{Transaction, TransactionType};

fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/signing/composite.txt")
}

fn vouchers() -> Vec<(u64, [u8; 32], u128, [u8; 32])> {
    vec![
        (13380, [0x11; 32], 1, [0; 32]),
        (13380, [0xa5; 32], 1_500_000_000_000_000_000, [0x3c; 32]),
        (u64::MAX, [0xff; 32], u128::MAX, [0xff; 32]),
    ]
}

fn readings() -> Vec<(String, [u8; 32], u64)> {
    vec![
        ("did:tenzro:machine:1".to_string(), [0x22; 32], 0),
        (
            "did:tenzro:machine:did:tenzro:human:5f0c8a52-6d0e-4c5f-9a43-0d6f1e2b7c11:7b1e9d3a-2c4f-4e8b-b6a1-3f5d7c9e0a12"
                .to_string(),
            [0x5a; 32],
            1_763_251_200_123,
        ),
        ("d".repeat(256), [0xff; 32], u64::MAX),
    ]
}

fn vectors() -> String {
    let mut out = String::from(
        "# voucher|chain_id|escrow_id|cumulative_le|binding|preimage\n\
         # reading|device_did|payload_digest|measured_at_ms|digest\n\
         # evidence|device_did|payload_digest|measured_at_ms|p256_signature|ml_dsa_signature|json\n\
         # transaction|chain_id|from|to|nonce|gas_limit|gas_price|timestamp|valid_until|amount_le|memo|tx_type_json|hash\n\
         # request|id|chain_id|from|to|nonce|gas_limit|gas_price|timestamp|valid_until|amount_le|public_key|p256_signature|ml_dsa_signature|json\n\
         # representative|context|message|representative|p256_digest\n\
         # account|public_key|slot\n\
         # enrolment|name|controller|capabilities|public_key|command\n\
         # update|release_key|platform|installed_version|envelope|status|version|release|path|length|sha256\n",
    );
    let mut messages: Vec<(SignatureContext, Vec<u8>)> = vec![
        (SignatureContext::SensorReading, vec![0x11; 32]),
        (SignatureContext::Transaction, Vec::new()),
        (
            SignatureContext::Transaction,
            (0..300u16).map(|i| (i % 251) as u8).collect(),
        ),
    ];
    for (chain_id, escrow_id, cumulative, binding) in vouchers() {
        let preimage = escrow_voucher_preimage(chain_id, &escrow_id, cumulative, &binding);
        out.push_str(&format!(
            "voucher|{chain_id}|{}|{}|{}|{}\n",
            hex::encode(escrow_id),
            hex::encode(cumulative.to_le_bytes()),
            hex::encode(binding),
            hex::encode(&preimage),
        ));
        messages.push((SignatureContext::EscrowVoucher, preimage));
    }
    for (device_did, payload_digest, measured_at_ms) in readings() {
        let digest = sensor_reading_digest(&device_did, &payload_digest, measured_at_ms);
        out.push_str(&format!(
            "reading|{device_did}|{}|{measured_at_ms}|{}\n",
            hex::encode(payload_digest),
            hex::encode(digest),
        ));
        messages.push((SignatureContext::SensorReading, digest.to_vec()));
    }
    let legs: [(Vec<u8>, Option<Vec<u8>>); 2] = [
        ((0..64).collect(), None),
        (
            vec![0xab; 64],
            Some((0..3309u16).map(|i| (i % 251) as u8).collect()),
        ),
    ];
    for ((device_did, payload_digest, measured_at_ms), (p256, ml_dsa)) in
        readings().into_iter().zip(legs)
    {
        let evidence = Evidence::SensorData {
            device_did: device_did.clone(),
            payload_digest,
            measured_at_ms,
            signature: CompositeSignature {
                classical: ClassicalProof::Raw {
                    signature: p256.clone(),
                },
                pq: ml_dsa.clone(),
            },
        };
        out.push_str(&format!(
            "evidence|{device_did}|{}|{measured_at_ms}|{}|{}|{}\n",
            hex::encode(payload_digest),
            hex::encode(&p256),
            hex::encode(ml_dsa.unwrap_or_default()),
            serde_json::to_string(&evidence).expect("evidence serializes"),
        ));
    }
    let transfers: [(u64, u8, u8, u64, u64, u64, i64, i64, u128, Option<&str>); 3] = [
        (
            13380,
            0x11,
            0x22,
            0,
            21_000,
            1_000_000_000,
            1_763_251_200_000,
            1_763_251_500_000,
            1,
            None,
        ),
        (
            13380,
            0xa5,
            0x5a,
            7,
            50_000,
            2_000_000_000,
            1_763_251_200_123,
            1_763_337_600_123,
            1_500_000_000_000_000_000,
            Some("sensor 4 reading 1290"),
        ),
        (
            u64::MAX,
            0xff,
            0x00,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            -1,
            i64::MAX,
            u128::MAX,
            Some(""),
        ),
    ];
    for (chain_id, from, to, nonce, gas_limit, gas_price, timestamp, valid_until, amount, memo) in
        transfers
    {
        let tx = Transaction {
            chain_id: ChainId(chain_id),
            from: Address([from; 32]),
            to: Address([to; 32]),
            nonce: Nonce(nonce),
            tx_type: TransactionType::Transfer { amount },
            gas_limit,
            gas_price,
            timestamp: Timestamp(timestamp),
            valid_until: Timestamp(valid_until),
            memo: memo.map(str::to_string),
        };
        let hash = tx.hash();
        out.push_str(&format!(
            "transaction|{chain_id}|{}|{}|{nonce}|{gas_limit}|{gas_price}|{timestamp}|{valid_until}|{}|{}|{}|{}\n",
            hex::encode(tx.from.0),
            hex::encode(tx.to.0),
            hex::encode(amount.to_le_bytes()),
            memo.unwrap_or_default(),
            serde_json::to_string(&tx.tx_type).expect("a transfer serializes"),
            hex::encode(hash.as_bytes()),
        ));
        messages.push((SignatureContext::Transaction, hash.as_bytes().to_vec()));
    }
    // The request a device sends for a signed transfer, and the transaction
    // the node rebuilds from it the way `tenzro_sendRawTransaction` reads its
    // params (crates/tenzro-node/src/rpc.rs, unsigned_transaction): its hash
    // is the one the device signed.
    let requests: [(u64, u64, u8, u8, u64, u64, u64, u64, u64, u128, bool); 2] = [
        (
            1,
            13380,
            0x11,
            0x22,
            3,
            21_000,
            1_000_000_000,
            1_763_251_200_000,
            1_763_251_500_000,
            250,
            false,
        ),
        (
            u64::MAX,
            13380,
            0xa5,
            0x5a,
            u64::MAX,
            50_000,
            2_000_000_000,
            1_763_251_200_123,
            1_763_337_600_123,
            u128::MAX,
            true,
        ),
    ];
    for (
        id,
        chain_id,
        from,
        to,
        nonce,
        gas_limit,
        gas_price,
        timestamp,
        valid_until,
        amount,
        hybrid,
    ) in requests
    {
        let tx = Transaction {
            chain_id: ChainId(chain_id),
            from: Address([from; 32]),
            to: Address([to; 32]),
            nonce: Nonce(nonce),
            tx_type: TransactionType::Transfer { amount },
            gas_limit,
            gas_price,
            timestamp: Timestamp(timestamp as i64),
            valid_until: Timestamp(valid_until as i64),
            memo: None,
        };
        let public_key: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(3)).collect();
        let p256: Vec<u8> = (0..64u8).map(|i| 0xff - i).collect();
        let ml_dsa: Vec<u8> = if hybrid {
            (0..3309u16).map(|i| (i % 7) as u8).collect()
        } else {
            Vec::new()
        };
        let tx_type = serde_json::to_string(&tx.tx_type).expect("a transfer serializes");
        let pq = if hybrid {
            format!(",\"pq\":\"{}\"", hex::encode(&ml_dsa))
        } else {
            String::new()
        };
        let json = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tenzro_sendRawTransaction\",\"params\":{{\
             \"from\":\"0x{}\",\"to\":\"0x{}\",\"value\":\"{amount}\",\"gas_limit\":{gas_limit},\
             \"gas_price\":{gas_price},\"nonce\":{nonce},\"chain_id\":{chain_id},\"timestamp\":{timestamp},\
             \"valid_until\":{valid_until},\"tx_type\":{tx_type},\"public_key\":\"{}\",\
             \"signature\":{{\"classical\":{{\"form\":\"raw\",\"signature\":\"{}\"}}{pq}}}}}}}",
            hex::encode(tx.from.0),
            hex::encode(tx.to.0),
            hex::encode(&public_key),
            hex::encode(&p256),
        );
        let request: serde_json::Value = serde_json::from_str(&json).expect("the request is JSON");
        let p = &request["params"];
        let rebuilt = Transaction {
            chain_id: ChainId(p["chain_id"].as_u64().unwrap()),
            from: Address::parse(p["from"].as_str().unwrap()).unwrap(),
            to: Address::parse(p["to"].as_str().unwrap()).unwrap(),
            nonce: Nonce(p["nonce"].as_u64().unwrap()),
            tx_type: serde_json::from_value(p["tx_type"].clone()).unwrap(),
            gas_limit: p["gas_limit"].as_u64().unwrap(),
            gas_price: p["gas_price"].as_u64().unwrap(),
            timestamp: Timestamp(p["timestamp"].as_u64().unwrap() as i64),
            valid_until: Timestamp(p["valid_until"].as_u64().unwrap() as i64),
            memo: None,
        };
        assert_eq!(
            rebuilt.hash(),
            tx.hash(),
            "the node rebuilds the transaction the device signed"
        );
        let signature: CompositeSignature = serde_json::from_value(p["signature"].clone())
            .expect("the signature is the node's form");
        assert_eq!(signature.pq.is_some(), hybrid);
        out.push_str(&format!(
            "request|{id}|{chain_id}|{}|{}|{nonce}|{gas_limit}|{gas_price}|{timestamp}|{valid_until}|{}|{}|{}|{}|{json}\n",
            hex::encode(tx.from.0),
            hex::encode(tx.to.0),
            hex::encode(amount.to_le_bytes()),
            hex::encode(&public_key),
            hex::encode(&p256),
            hex::encode(&ml_dsa),
        ));
    }
    for (context, message) in messages {
        out.push_str(&format!(
            "representative|{}|{}|{}|{}\n",
            std::str::from_utf8(context.as_bytes()).expect("contexts are ASCII"),
            hex::encode(&message),
            hex::encode(message_representative(context, &message)),
            hex::encode(signing_digest(context, &message)),
        ));
    }
    // The account a device's P-256 key holds, as the ledger derives it, and
    // the command its operator runs to register the device (the CLI's own
    // test parses these lines: crates/tenzro-cli/src/commands/identity.rs).
    use p256::elliptic_curve::sec1::ToSec1Point;
    for secret in [[0x01u8; 32], [0x7fu8; 32]] {
        let key = p256::SecretKey::from_slice(&secret).expect("a valid P-256 scalar");
        let point = key.public_key().to_sec1_point(false);
        let xy = &point.as_bytes()[1..];
        out.push_str(&format!(
            "account|{}|{}\n",
            hex::encode(xy),
            hex::encode(tenzro_crypto::composite::account_slot(xy))
        ));
        let (name, controller, capabilities) = (
            "sensor-1",
            "did:tenzro:human:5f0c8a52-6d0e-4c5f-9a43-0d6f1e2b7c11",
            "sensor.read,escrow.voucher",
        );
        out.push_str(&format!(
            "enrolment|{name}|{controller}|{capabilities}|{xy}|tenzro identity register \
             --identity-type machine --name {name} --controller {controller} --public-key {xy} \
             --capabilities {capabilities}\n",
            xy = hex::encode(xy)
        ));
    }
    out.push_str(&update_vectors());
    out
}

#[test]
fn the_signing_vectors_are_what_the_ledger_verifies() {
    let built = vectors();
    if std::env::var_os("TENZRO_WRITE_FIXTURES").is_some() {
        std::fs::write(fixture(), &built).expect("fixture written");
    }
    let kept = std::fs::read_to_string(fixture()).expect("sdk/fixtures/signing/composite.txt");
    assert_eq!(
        kept, built,
        "signing bytes changed: rerun with TENZRO_WRITE_FIXTURES=1 if deliberate"
    );
}

/// The same value with every object's keys in sorted order, so the bytes do not
/// depend on whether another crate in the build turns on serde_json's
/// `preserve_order`.
fn sorted(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| (k, sorted(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// Signed firmware updates on the release channel's format (a targets
/// document in an envelope, signed by the release key under the channel's
/// domain; docs/UPDATE-MANIFEST.md): what a device takes, and what it
/// refuses and why.
fn update_vectors() -> String {
    use base64::Engine as _;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest, Sha256};

    const DOMAIN: &[u8] = b"tenzro-update/1\ntargets\n";
    let release = SigningKey::from_slice(&[0x5e; 32]).expect("a valid scalar");
    let other = SigningKey::from_slice(&[0x6f; 32]).expect("a valid scalar");
    let sec1 = |k: &SigningKey| k.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let sign = |k: &SigningKey, payload: &[u8]| -> Signature {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(payload)
            .finalize()
            .into();
        k.sign_prehash(&digest).expect("signing a prehash")
    };
    let entry = |platform: &str, name: &str, path: &str, byte: u8, length: u64| {
        sorted(serde_json::json!({
            "platform": platform, "name": name, "path": path, "length": length,
            "sha256": hex::encode([byte; 32]),
        }))
    };
    let document = |version: u64, files: Vec<serde_json::Value>| -> Vec<u8> {
        serde_json::to_vec(&sorted(serde_json::json!({
            "_type": "targets", "spec": "tenzro-update/1", "version": version,
            "release": "0.2.2", "class": "C0", "description": "Firmware \"0.2.2\" for small devices",
            "files": files,
        })))
        .expect("a document")
    };
    let files = vec![
        entry(
            "x86_64-linux",
            "tenzro-node",
            "0.2.2/x86_64-linux/tenzro-node",
            0x01,
            52_428_800,
        ),
        entry(
            "xtensa-esp32s3",
            "firmware",
            "0.2.2/xtensa-esp32s3/tenzro.bin",
            0x53,
            1_310_720,
        ),
        entry(
            "riscv32-esp32p4",
            "firmware",
            "0.2.2/riscv32-esp32p4/tenzro.bin",
            0x54,
            1_572_864,
        ),
    ];
    let v7 = document(7, files.clone());
    let v8 = document(8, files.clone());
    let twice = document(9, vec![files[1].clone(), files[1].clone()]);
    let envelope = |payload: &[u8], sigs: Vec<(&SigningKey, String)>| {
        sorted(serde_json::json!({
            "payload": base64::engine::general_purpose::STANDARD.encode(payload),
            "signatures": sigs.into_iter().map(|(k, sig)| serde_json::json!({
                "keyid": hex::encode(Sha256::digest(sec1(k))), "sig": sig,
            })).collect::<Vec<_>>(),
        }))
        .to_string()
    };
    let raw = |k: &SigningKey, p: &[u8]| hex::encode(sign(k, p).to_bytes());
    let der = |k: &SigningKey, p: &[u8]| hex::encode(sign(k, p).to_der().as_bytes());
    let s3 = (
        "0.2.2/xtensa-esp32s3/tenzro.bin",
        1_310_720u64,
        hex::encode([0x53u8; 32]),
    );
    let cases: Vec<(&str, u64, String, &str, Option<u64>)> = vec![
        // Another key's signature first, then the release key's (raw r || s).
        (
            "xtensa-esp32s3",
            6,
            envelope(
                &v7,
                vec![(&other, raw(&other, &v7)), (&release, raw(&release, &v7))],
            ),
            "ok",
            Some(7),
        ),
        // The release key's signature in DER, as cosign writes it.
        (
            "xtensa-esp32s3",
            0,
            envelope(&v7, vec![(&release, der(&release, &v7))]),
            "ok",
            Some(7),
        ),
        // The document the device already installed, or an older one: a roll back.
        (
            "xtensa-esp32s3",
            7,
            envelope(&v7, vec![(&release, raw(&release, &v7))]),
            "rollback",
            None,
        ),
        // No image for this platform.
        (
            "riscv32-esp32c6",
            6,
            envelope(&v7, vec![(&release, raw(&release, &v7))]),
            "no_target",
            None,
        ),
        // Signed by another key only.
        (
            "xtensa-esp32s3",
            6,
            envelope(&v7, vec![(&other, raw(&other, &v7))]),
            "signature",
            None,
        ),
        // A newer document carrying the release key's signature over the older one.
        (
            "xtensa-esp32s3",
            6,
            envelope(&v8, vec![(&release, raw(&release, &v7))]),
            "signature",
            None,
        ),
        // Two images for one platform.
        (
            "xtensa-esp32s3",
            6,
            envelope(&twice, vec![(&release, raw(&release, &twice))]),
            "response",
            None,
        ),
    ];
    let mut out = String::new();
    for (platform, installed, env, status, version) in cases {
        let (path, length, sha) = match version {
            Some(_) => (s3.0.to_string(), s3.1.to_string(), s3.2.clone()),
            None => (String::new(), String::new(), String::new()),
        };
        out.push_str(&format!(
            "update|{}|{platform}|{installed}|{env}|{status}|{}|{}|{path}|{length}|{sha}\n",
            hex::encode(sec1(&release)),
            version.map(|v| v.to_string()).unwrap_or_default(),
            if version.is_some() { "0.2.2" } else { "" },
        ));
    }
    out
}
