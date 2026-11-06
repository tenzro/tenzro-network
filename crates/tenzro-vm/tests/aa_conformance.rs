//! Conformance of the EVM account-abstraction surface with the published
//! standards: ERC-4337 EntryPoint v0.9 hashing and packing, ERC-7579
//! interface identifiers and execution encoding, and EIP-7951 P256VERIFY.
//!
//! The user operation hashes below were computed independently from the
//! EntryPoint v0.9 sources; the one with a paymaster signature is also what
//! the EntryPoint v0.9 contract on Ethereum mainnet returns from
//! `getUserOpHash` for the same operation. The P256VERIFY cases are the
//! EIP-7951 test vectors.

use tenzro_vm::aa_execution::{EXECUTE_SELECTOR, Execution, encode_batch, encode_single};
use tenzro_vm::account_abstraction::{
    ENTRY_POINT_V09, INITCODE_EIP7702_MARKER, Nonce, PackedUserOperation, UserOperation,
    domain_separator,
};
use tenzro_vm::erc7579::*;
use tenzro_vm::precompiles::PRECOMPILE_P256VERIFY;
use tenzro_vm::traits::VmState;
use tenzro_vm::{ContractCall, MultiVmRuntime, StateAdapter, VmConfig, VmType};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

fn sel(sig: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let d = Keccak256::digest(sig.as_bytes());
    [d[0], d[1], d[2], d[3]]
}

fn op() -> UserOperation {
    UserOperation {
        sender: vec![0x11; 20],
        nonce: Nonce {
            key: [0x01; 24],
            seq: 7,
        }
        .to_bytes(),
        factory: vec![0x22; 20],
        factory_data: vec![0xaa, 0xbb],
        call_data: h("e9ae5c53"),
        call_gas_limit: 100_000,
        verification_gas_limit: 50_000,
        pre_verification_gas: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        paymaster: vec![0x33; 20],
        paymaster_verification_gas_limit: 40_000,
        paymaster_post_op_gas_limit: 10_000,
        paymaster_data: h("010203"),
        paymaster_signature: vec![0x44; 65],
        signature: vec![],
    }
}

#[test]
fn erc4337_domain_is_erc4337_version_1() {
    assert_eq!(
        domain_separator(1, &ENTRY_POINT_V09),
        h32("0xc3770890383ef71feb6849938be9093ba0de335ab68635a794748275c616d521")
    );
}

#[test]
fn erc4337_packing_matches_entry_point_v09() {
    let p = op().to_packed();
    assert_eq!(
        p.init_code,
        h("2222222222222222222222222222222222222222aabb")
    );
    assert_eq!(
        p.paymaster_and_data,
        h(
            "0x333333333333333333333333333333333333333300000000000000000000000000009c40000000000000000000000000000027100102034444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444004122e325a297439656"
        )
    );
    let mut agl = [0u8; 32];
    agl[..16].copy_from_slice(&50_000u128.to_be_bytes());
    agl[16..].copy_from_slice(&100_000u128.to_be_bytes());
    assert_eq!(p.account_gas_limits, agl);
    assert_eq!(p.to_user_op().unwrap(), op());
}

#[test]
fn erc4337_user_op_hash_matches_entry_point_v09() {
    // Paymaster signature present: left out of the hash, magic kept.
    assert_eq!(
        op().hash(1, &ENTRY_POINT_V09, None).unwrap(),
        h32("0xdf8010c18e18687e3cbaad430345fb4525329dcc642f72bc58b8e93ae980b273")
    );
    let mut unsigned = op();
    unsigned.paymaster_signature.clear();
    assert_eq!(
        unsigned.hash(1, &ENTRY_POINT_V09, None).unwrap(),
        h32("0xcd931d036981285cd5ed8640dc096f72b851fb9b367eecb52ee6a28f40ada9cb")
    );
    // EIP-7702 account: the init code hash is keccak256(delegate ‖ initCode[20..]).
    let mut eip7702 = unsigned;
    eip7702.factory = INITCODE_EIP7702_MARKER.to_vec();
    eip7702.factory_data = h("cafe");
    assert_eq!(
        eip7702
            .hash(1, &ENTRY_POINT_V09, Some(&[0x77; 20]))
            .unwrap(),
        h32("0xf586f10220793fc2f9cac726275a7dbeac1e659bcc55f037bdffdafed1a9afbd")
    );
}

#[test]
fn erc4337_paymaster_signature_length_cannot_reach_the_fixed_fields() {
    let mut p: PackedUserOperation = op().to_packed();
    let n = p.paymaster_and_data.len();
    p.paymaster_and_data[n - 10..n - 8].copy_from_slice(&0xffffu16.to_be_bytes());
    assert!(p.hash(1, &ENTRY_POINT_V09, None).is_err());
}

#[test]
fn erc7579_identifiers_are_the_standard_ones() {
    let cases: [([u8; 4], &str); 14] = [
        (SELECTOR_EXECUTE, "execute(bytes32,bytes)"),
        (
            SELECTOR_EXECUTE_FROM_EXECUTOR,
            "executeFromExecutor(bytes32,bytes)",
        ),
        (SELECTOR_ACCOUNT_ID, "accountId()"),
        (
            SELECTOR_SUPPORTS_EXECUTION_MODE,
            "supportsExecutionMode(bytes32)",
        ),
        (SELECTOR_SUPPORTS_MODULE, "supportsModule(uint256)"),
        (
            SELECTOR_INSTALL_MODULE,
            "installModule(uint256,address,bytes)",
        ),
        (
            SELECTOR_UNINSTALL_MODULE,
            "uninstallModule(uint256,address,bytes)",
        ),
        (
            SELECTOR_IS_MODULE_INSTALLED,
            "isModuleInstalled(uint256,address,bytes)",
        ),
        (SELECTOR_ON_INSTALL, "onInstall(bytes)"),
        (SELECTOR_ON_UNINSTALL, "onUninstall(bytes)"),
        (SELECTOR_IS_MODULE_TYPE, "isModuleType(uint256)"),
        (SELECTOR_IS_INITIALIZED, "isInitialized(address)"),
        (
            SELECTOR_VALIDATE_USER_OP,
            "validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)",
        ),
        (
            SELECTOR_IS_VALID_SIGNATURE_WITH_SENDER,
            "isValidSignatureWithSender(address,bytes32,bytes)",
        ),
    ];
    for (constant, sig) in cases {
        assert_eq!(constant, sel(sig), "{sig}");
    }
    assert_eq!(EXECUTE_SELECTOR, SELECTOR_EXECUTE);
    assert_eq!(
        [
            MODULE_TYPE_VALIDATOR,
            MODULE_TYPE_EXECUTOR,
            MODULE_TYPE_FALLBACK,
            MODULE_TYPE_HOOK
        ],
        [1, 2, 3, 4]
    );
}

#[test]
fn erc7579_execution_encoding_matches_the_abi() {
    let a = Execution {
        target: [0x0b; 20],
        value: 5,
        call_data: h("a9059cbb"),
    };
    let b = Execution {
        target: [0x0c; 20],
        value: 0,
        call_data: vec![],
    };
    assert_eq!(
        encode_single(&a),
        h(
            "0xe9ae5c530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000380b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000000000000000000000000000000000000000000000000000005a9059cbb0000000000000000"
        )
    );
    assert_eq!(
        encode_batch(&[a, b]),
        h(
            "0xe9ae5c530100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004a9059cbb000000000000000000000000000000000000000000000000000000000000000000000000000000000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000"
        )
    );
}

// EIP-7951 P256VERIFY.

const CALLER: [u8; 20] = [0xc0; 20];
const DELEGATE_CALLER: [u8; 20] = [0xc1; 20];

/// Code that copies its calldata to memory, calls `0x100` with it using
/// `opcode` (STATICCALL or DELEGATECALL) and `gas`, and returns the output
/// word followed by the success flag.
fn p256_caller(opcode: u8, gas: u16) -> Vec<u8> {
    let mut c = vec![0x36, 0x60, 0x00, 0x60, 0x00, 0x37];
    c.extend_from_slice(&[
        0x60, 0x20, 0x61, 0x02, 0x00, 0x60, 0xa0, 0x60, 0x00, 0x61, 0x01, 0x00,
    ]);
    c.push(0x61);
    c.extend_from_slice(&gas.to_be_bytes());
    c.push(opcode);
    c.extend_from_slice(&[0x61, 0x02, 0x20, 0x52]);
    c.extend_from_slice(&[0x60, 0x40, 0x61, 0x02, 0x00, 0xf3]);
    c
}

async fn eth_call(rt: &MultiVmRuntime, state: &StateAdapter, to: &[u8], input: Vec<u8>) -> Vec<u8> {
    let call = ContractCall::new(
        vec![0xa1; 20],
        to.to_vec(),
        input,
        0,
        1_000_000,
        VmType::Evm,
    );
    let r = rt.call(&call, state).await.unwrap();
    assert!(r.success);
    r.output
}

#[derive(serde::Deserialize)]
struct Vector {
    input: String,
    valid: bool,
}

#[tokio::test]
async fn eip7951_p256verify_answers_every_test_vector() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("fixtures/eip7951/vectors.json")).unwrap();
    assert!(vectors.len() > 700);
    let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let state = StateAdapter::new();
    let one = {
        let mut w = vec![0u8; 32];
        w[31] = 1;
        w
    };
    for (i, v) in vectors.iter().enumerate() {
        let out = eth_call(&rt, &state, &PRECOMPILE_P256VERIFY, h(&v.input)).await;
        let expected = if v.valid { one.clone() } else { Vec::new() };
        assert_eq!(out, expected, "vector {i}");
    }
}

#[tokio::test]
async fn eip7951_p256verify_costs_6900_and_answers_any_call_type() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("fixtures/eip7951/vectors.json")).unwrap();
    let valid = vectors.iter().find(|v| v.valid).unwrap();
    let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    for (gas, ok) in [(6_899u16, false), (6_900, true)] {
        let mut state = StateAdapter::new();
        state.set_code(&CALLER, p256_caller(0xfa, gas));
        state.set_code(&DELEGATE_CALLER, p256_caller(0xf4, gas));
        for at in [CALLER, DELEGATE_CALLER] {
            let out = eth_call(&rt, &state, &at, h(&valid.input)).await;
            assert_eq!(out[63], ok as u8, "call succeeded with gas {gas}");
            assert_eq!(out[31], ok as u8, "output word with gas {gas}");
        }
    }
    // Wrong input length: success with empty output.
    let state = StateAdapter::new();
    let short = h(&valid.input)[..159].to_vec();
    assert!(
        eth_call(&rt, &state, &PRECOMPILE_P256VERIFY, short)
            .await
            .is_empty()
    );
}
