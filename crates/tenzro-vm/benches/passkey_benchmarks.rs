//! Criterion benches for the passkey / hardware validator chain.
//!
//! Covers:
//! - HardwareSignerValidator::validate_user_op (the ECDSA secp256k1 verify
//!   path that fires on every UserOp signed with a Ledger / Trezor / GridPlus).
//! - HardwareSignerValidator::install_from_init_data (the setup-time cost
//!   that runs once per `tenzro_addHardwareSigner` call).
//!
//! Run with: cargo bench -p tenzro-vm --bench passkey_benchmarks

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use tenzro_vm::aa_validators::IValidator;
use tenzro_vm::erc7579::{
    HARDWARE_VALIDATOR_LEDGER, HardwareSignerConfig, HardwareSignerValidator,
};

fn deterministic_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_add(1);
    }
    SigningKey::from_bytes(&bytes.into()).expect("valid secp256k1 scalar")
}

fn dummy_user_op(sender: Vec<u8>, sig: Vec<u8>) -> tenzro_vm::account_abstraction::UserOperation {
    tenzro_vm::account_abstraction::UserOperation {
        sender,
        nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
        factory: vec![],
        factory_data: vec![],
        call_data: vec![],
        call_gas_limit: 100_000,
        verification_gas_limit: 50_000,
        pre_verification_gas: 21_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        paymaster: vec![],
        paymaster_verification_gas_limit: 0,
        paymaster_post_op_gas_limit: 0,
        paymaster_data: vec![],
        signature: sig,
    }
}

fn bench_hardware_validate_user_op(c: &mut Criterion) {
    let validator = HardwareSignerValidator::new(HARDWARE_VALIDATOR_LEDGER);
    let sender = vec![0xAB; 20];
    let sk = deterministic_signing_key(7);
    let pubkey = sk.verifying_key().to_sec1_point(true).as_bytes().to_vec();

    validator
        .install_for(
            sender.clone(),
            HardwareSignerConfig {
                device_kind: "ledger".into(),
                public_key: pubkey,
                required_always: true,
                required_above_wei: None,
                label: None,
            },
        )
        .unwrap();

    let op_hash = [0x42u8; 32];
    let sig: Signature = sk.sign(&op_hash);
    let sig_bytes = sig.to_bytes().to_vec();
    let op = dummy_user_op(sender, sig_bytes);

    c.bench_function("hardware_validator_validate_user_op", |b| {
        b.iter(|| {
            let _ = black_box(validator.validate_user_op(black_box(&op), black_box(&op_hash)));
        });
    });
}

fn bench_hardware_install_from_init_data(c: &mut Criterion) {
    let validator = HardwareSignerValidator::new(HARDWARE_VALIDATOR_LEDGER);
    // 33-byte SEC1 compressed pubkey
    let init = serde_json::json!({
        "device_kind": "ledger",
        "public_key": vec![0x02u8; 33],
        "required_always": true,
        "required_above_wei": null,
        "label": "Ledger Nano X"
    });
    let init_bytes = serde_json::to_vec(&init).unwrap();

    c.bench_function("hardware_validator_install_from_init_data", |b| {
        // Fresh account each iteration so the install path actually runs.
        let mut counter: u64 = 0;
        b.iter(|| {
            let mut account = vec![0u8; 20];
            account[0..8].copy_from_slice(&counter.to_le_bytes());
            counter = counter.wrapping_add(1);
            validator
                .install_from_init_data(account, black_box(&init_bytes))
                .unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_hardware_validate_user_op,
    bench_hardware_install_from_init_data
);
criterion_main!(benches);
