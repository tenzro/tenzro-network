//! Integration tests for tenzro-wallet

use tempfile::TempDir;
use tenzro_types::AssetId;
use tenzro_types::primitives::Address;
use tenzro_wallet::{
    WalletId, WalletIdentity,
    builder::TransactionBuilder,
    service::{TenzroWalletService, WalletServiceConfig},
    traits::WalletService,
};

use tenzro_crypto::HybridSigner;
use tenzro_crypto::composite::testing::TestHybridSigner;

/// Bind the in-memory signer for `seed`, standing in for the passkey or
/// secure element that holds the real key.
fn bind_signer(service: &TenzroWalletService, wallet_id: &WalletId, seed: u8) {
    service.set_hybrid_signer(
        wallet_id.clone(),
        std::sync::Arc::new(TestHybridSigner::hybrid(seed)),
    );
}

fn pk(seed: u8) -> tenzro_crypto::CompositePublicKey {
    TestHybridSigner::hybrid(seed).public_key().clone()
}

/// A human identity for tests. `seed` distinguishes one test identity from
/// another — the wallet address derives from the identity key, so two wallets
/// only differ if their identities do.
fn human_identity(seed: u8) -> WalletIdentity {
    WalletIdentity::human(vec![seed; 16], pk(seed)).unwrap()
}

/// A machine identity — rooted in a TPM / Secure Enclave key, no passkey.
fn machine_identity(seed: u8) -> WalletIdentity {
    WalletIdentity::machine(format!("machine-{seed}"), pk(seed)).unwrap()
}

fn service(temp_dir: &TempDir) -> TenzroWalletService {
    let config = WalletServiceConfig::new(temp_dir.path().to_path_buf());
    TenzroWalletService::with_config(config).unwrap()
}

#[tokio::test]
async fn test_wallet_provisioning_and_signing() {
    let temp_dir = TempDir::new().unwrap();
    let service = service(&temp_dir);

    let wallet = service.provision_wallet(human_identity(1)).await.unwrap();

    // The wallet carries the identity's public key, never its secret half.
    assert_eq!(wallet.public_key, pk(1));
    bind_signer(&service, &wallet.wallet_id, 1);

    let data = b"test data for signing";
    let signature = service
        .sign_data(
            &wallet.wallet_id,
            tenzro_crypto::composite::SignatureContext::X402Payment,
            data,
        )
        .await
        .unwrap();

    // Hybrid signature: classical leg from the identity signer + the
    // mandatory ML-DSA-65 leg.
    assert!(signature.has_classical_leg());
    assert_eq!(signature.pq.as_ref().map(Vec::len), Some(3309));
}

#[tokio::test]
async fn test_wallet_transaction_signing() {
    let temp_dir = TempDir::new().unwrap();
    let service = service(&temp_dir);

    let wallet = service.provision_wallet(human_identity(2)).await.unwrap();
    bind_signer(&service, &wallet.wallet_id, 2);

    let nonce = service.next_nonce(&wallet.address);
    let tx = TransactionBuilder::default_chain()
        .from_wallet(&wallet)
        .to(Address::new([2u8; 32]))
        .nonce(nonce)
        .transfer(1000)
        .build_validated()
        .unwrap();

    let signature = service
        .sign_transaction(&wallet.wallet_id, &tx)
        .await
        .unwrap();

    assert!(signature.has_classical_leg());
    assert_eq!(signature.pq.as_ref().map(Vec::len), Some(3309));
}

#[tokio::test]
async fn test_balance_tracking() {
    let temp_dir = TempDir::new().unwrap();
    let service = service(&temp_dir);

    let wallet = service.provision_wallet(human_identity(3)).await.unwrap();

    let balance = service
        .get_balance(&wallet.address, &AssetId::tnzo())
        .await
        .unwrap();
    assert_eq!(balance.available, 0);

    let tracker = service.balance_tracker();
    tracker.add_balance(&wallet.address, &AssetId::tnzo(), 1000);

    let balance = service
        .get_balance(&wallet.address, &AssetId::tnzo())
        .await
        .unwrap();
    assert_eq!(balance.available, 1000);
}

/// A machine wallet needs no passkey: an autonomous machine roots its key in
/// a TPM or Secure Enclave, so requiring a human credential would make
/// unattended provisioning impossible.
#[tokio::test]
async fn test_machine_wallet_needs_no_passkey() {
    let temp_dir = TempDir::new().unwrap();
    let service = service(&temp_dir);

    let identity = machine_identity(9);
    assert!(identity.is_machine());
    assert_eq!(identity.kind(), "machine:secure-element");

    let wallet = service.provision_wallet(identity).await.unwrap();
    assert_eq!(wallet.public_key, pk(9));
}

/// A wallet cannot be built without key material behind it. These are the
/// constructor's refusals — the reason "no wallet without an identity" is a
/// compile-time property rather than a runtime check.
#[test]
fn test_identity_rejects_empty_credentials() {
    let pk = pk(1);
    assert!(WalletIdentity::human(Vec::new(), pk.clone()).is_err());
    assert!(WalletIdentity::machine("", pk.clone()).is_err());
    assert!(WalletIdentity::machine("   ", pk).is_err());
}

#[tokio::test]
async fn test_multiple_wallets() {
    let temp_dir = TempDir::new().unwrap();
    let service = service(&temp_dir);

    // Distinct identities — the address derives from the identity key, so
    // two wallets differ exactly when their identities do.
    let wallet1 = service.provision_wallet(human_identity(11)).await.unwrap();
    let wallet2 = service.provision_wallet(human_identity(12)).await.unwrap();
    let wallet3 = service
        .provision_wallet(machine_identity(13))
        .await
        .unwrap();

    assert_ne!(wallet1.wallet_id, wallet2.wallet_id);
    assert_ne!(wallet2.wallet_id, wallet3.wallet_id);
    assert_ne!(wallet1.address, wallet2.address);
    assert_ne!(wallet2.address, wallet3.address);

    let wallets = service.list_wallets().await.unwrap();
    assert_eq!(wallets.len(), 3);
}

#[tokio::test]
async fn test_asset_support() {
    let temp_dir = TempDir::new().unwrap();
    let service = service(&temp_dir);

    let wallet = service.provision_wallet(human_identity(4)).await.unwrap();

    assert!(wallet.supports_asset(&AssetId::tnzo()));
    assert!(wallet.supports_asset(&AssetId::from("USDT")));
    assert!(wallet.supports_asset(&AssetId::from("USDC")));

    let assets = service.supported_assets().await;
    assert!(assets.contains(&AssetId::tnzo()));
}
