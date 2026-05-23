//! Cross-crate consistency: the client-side EIP-712 hash computed by
//! `tenzro-wallet::userop::user_op_hash` MUST equal the on-chain hash
//! computed by `tenzro_vm::account_abstraction::UserOperation::hash`
//! byte-for-byte. Drift between the two = unsignable UserOps. This test
//! is the contract enforcement.

use tenzro_vm::account_abstraction::UserOperation as VmUserOp;
use tenzro_wallet::userop::{user_op_hash, UserOp as WalletUserOp};

fn paired_ops() -> (WalletUserOp, VmUserOp) {
    let wallet = WalletUserOp {
        sender: vec![0x11; 20],
        nonce: 42,
        factory: vec![0x22; 20],
        factory_data: vec![0xaa, 0xbb, 0xcc],
        call_data: vec![0x42; 32],
        call_gas_limit: 250_000,
        verification_gas_limit: 75_000,
        pre_verification_gas: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_500_000_000,
        paymaster: vec![0x33; 20],
        paymaster_verification_gas_limit: 40_000,
        paymaster_post_op_gas_limit: 30_000,
        paymaster_data: vec![0xde, 0xad, 0xbe, 0xef],
        signature: vec![],
    };
    let vm = VmUserOp {
        sender: wallet.sender.clone(),
        nonce: wallet.nonce,
        factory: wallet.factory.clone(),
        factory_data: wallet.factory_data.clone(),
        call_data: wallet.call_data.clone(),
        call_gas_limit: wallet.call_gas_limit,
        verification_gas_limit: wallet.verification_gas_limit,
        pre_verification_gas: wallet.pre_verification_gas,
        max_fee_per_gas: wallet.max_fee_per_gas,
        max_priority_fee_per_gas: wallet.max_priority_fee_per_gas,
        paymaster: wallet.paymaster.clone(),
        paymaster_verification_gas_limit: wallet.paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit: wallet.paymaster_post_op_gas_limit,
        paymaster_data: wallet.paymaster_data.clone(),
        signature: wallet.signature.clone(),
    };
    (wallet, vm)
}

#[test]
fn wallet_hash_matches_entry_point_hash_typical_op() {
    let (wallet_op, vm_op) = paired_ops();
    let entry_point = vec![0xee; 20];
    let chain_id = 1337;

    let wallet_h = user_op_hash(&wallet_op, chain_id, &entry_point);
    let vm_h = vm_op.hash(chain_id, &entry_point);

    assert_eq!(
        wallet_h.to_vec(),
        vm_h,
        "wallet client-side EIP-712 hash diverged from EntryPoint hash"
    );
}

#[test]
fn wallet_hash_matches_for_minimal_op() {
    let wallet = WalletUserOp {
        sender: vec![0x01; 20],
        nonce: 0,
        factory: vec![],
        factory_data: vec![],
        call_data: vec![0xff],
        call_gas_limit: 1,
        verification_gas_limit: 1,
        pre_verification_gas: 1,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 0,
        paymaster: vec![],
        paymaster_verification_gas_limit: 0,
        paymaster_post_op_gas_limit: 0,
        paymaster_data: vec![],
        signature: vec![],
    };
    let vm = VmUserOp {
        sender: wallet.sender.clone(),
        nonce: wallet.nonce,
        factory: wallet.factory.clone(),
        factory_data: wallet.factory_data.clone(),
        call_data: wallet.call_data.clone(),
        call_gas_limit: wallet.call_gas_limit,
        verification_gas_limit: wallet.verification_gas_limit,
        pre_verification_gas: wallet.pre_verification_gas,
        max_fee_per_gas: wallet.max_fee_per_gas,
        max_priority_fee_per_gas: wallet.max_priority_fee_per_gas,
        paymaster: wallet.paymaster.clone(),
        paymaster_verification_gas_limit: wallet.paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit: wallet.paymaster_post_op_gas_limit,
        paymaster_data: wallet.paymaster_data.clone(),
        signature: wallet.signature.clone(),
    };
    let ep = vec![0x99; 20];
    assert_eq!(user_op_hash(&wallet, 1, &ep).to_vec(), vm.hash(1, &ep));
}

#[test]
fn wallet_hash_matches_across_chain_ids() {
    let (wallet_op, vm_op) = paired_ops();
    let entry_point = vec![0xee; 20];
    for chain_id in [1u64, 1337, 0x10ED20, 0x10ED21, u64::MAX] {
        assert_eq!(
            user_op_hash(&wallet_op, chain_id, &entry_point).to_vec(),
            vm_op.hash(chain_id, &entry_point),
            "hash mismatch at chain_id={chain_id}"
        );
    }
}
